//! Send synthetic input to a browser launched by this probe and read the page's
//! own observations back through the production CDP snapshot route.
//!
//! The event-posting APIs cannot report receipt, so a completed tool call is not
//! the verdict. Each action is compared with state the fixture page recorded.
//!
//! Run with:
//!
//! ```text
//! cargo run -p cerebellum --example live_synthetic_input
//! ```

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("this probe drives macOS synthetic input and has nothing to run here");
}

#[cfg(target_os = "macos")]
#[tokio::main]
async fn main() {
    if let Err(reason) = macos_probe::run().await {
        eprintln!("PROBE FAILED: {reason}");
        if cerebellum_macos::screen_is_locked() == Some(true) {
            eprintln!(
                "  the screen is locked. A browser launched now may not realise a window, so \
                 re-run unlocked before treating missing input observations as a delivery defect."
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
    use std::collections::BTreeSet;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use cerebellum::browser_config::BrowserConfig;
    use cerebellum::management;
    use cerebellum::Planes;
    use cerebellum_computer::platform::ProcessGrant;
    use cerebellum_core::health::HealthState;
    use serde::Deserialize;
    use serde_json::{json, Value};
    use subc_protocol::session::ModuleControlRequest;
    use subc_protocol::{
        BindIdentity, Flags, Frame, FrameType, Priority, RouteTarget, PROTOCOL_VERSION,
    };
    use tokio::sync::mpsc;

    use super::cingulate_answer::answer_cards;

    const BROWSER_CANDIDATES: &[&str] = &[
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    ];
    const TOOL_CHANNEL: u16 = 9;
    const TOOL_EPOCH: u32 = 3;
    const MANAGEMENT_CHANNEL: u16 = 4;
    const MANAGEMENT_EPOCH: u32 = 1;
    const GRANTEE: &str = "pj-live-synthetic-input-probe";
    const CONVERSATION: &str = "live-synthetic-input-probe";
    const INPUT_LABEL: &str = "Synthetic input text";
    const TYPE_TEXT: &str = "Cerebellum café";
    const KEY_REPORT_PREFIX: &str = "KEY_REPORT=";
    const EXPECTED_CHORD: &str = "control+shift+k";

    const PAGE: &str = r#"<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Cerebellum Synthetic Input Probe</title>
<style>
  html, body { margin: 0; height: 100%; font: 16px system-ui, sans-serif; }
  #scrollbox { position: fixed; inset: 0; overflow: auto; background: #f5f7fb; }
  main { box-sizing: border-box; min-height: 1600px; padding: 24px 36px; }
  input { display: block; width: 420px; padding: 10px; font-size: 18px; }
  .report { margin: 8px 0; font-family: ui-monospace, monospace; }
  .zone { display: block; width: 440px; height: 90px; margin-top: 34px; border: 2px solid #345; border-radius: 8px; background: white; }
  #drag-zone { margin-top: 42px; }
  .tail { height: 900px; }
</style>
</head>
<body>
<div id="scrollbox" tabindex="-1">
<main>
  <h1>Synthetic input delivery probe</h1>
  <label>Text sent by the probe <input id="probe-input" aria-label="Synthetic input text" autocomplete="off"></label>
  <div class="report" id="key-report">KEY_REPORT=none</div>
  <div class="report" id="scroll-report">SCROLL_REPORT=0</div>
  <div class="report" id="move-report">MOVE_REPORT=none</div>
  <div class="report" id="drag-report">DRAG_REPORT=none</div>
  <button class="zone" id="move-zone" type="button" aria-label="Synthetic move zone">Move target</button>
  <button class="zone" id="drag-zone" type="button" aria-label="Synthetic drag zone">Drag target</button>
  <div class="tail" aria-hidden="true"></div>
</main>
</div>
<script>
  // Report to the SERVER as well as into the DOM. Every DOM readback in this
  // probe travels through the CDP accessibility tree, and Chromium may decline
  // to populate that tree for a window that is not frontmost -- which is
  // exactly the state this probe must measure in. A server report does not
  // depend on the tree, on focus, or on CDP, so it can tell "the event never
  // arrived" apart from "the page could not be read".
  const tell = (what) => { try { navigator.sendBeacon('/report?' + encodeURIComponent(what)); } catch (e) {} };

  const input = document.getElementById('probe-input');
  const scrollbox = document.getElementById('scrollbox');
  const keyReport = document.getElementById('key-report');
  const scrollReport = document.getElementById('scroll-report');
  const moveReport = document.getElementById('move-report');
  const dragReport = document.getElementById('drag-report');
  const moveZone = document.getElementById('move-zone');
  const dragZone = document.getElementById('drag-zone');

  input.focus({preventScroll: true});
  input.addEventListener('input', () => tell('type=' + input.value));
  document.addEventListener('keydown', event => {
    if (event.ctrlKey && event.shiftKey && !event.metaKey && event.key.toLowerCase() === 'k') {
      keyReport.textContent = 'KEY_REPORT=control+shift+k';
      tell('keys=control+shift+k');
      event.preventDefault();
    }
  }, true);
  scrollbox.addEventListener('scroll', () => {
    scrollReport.textContent = `SCROLL_REPORT=${scrollbox.scrollTop}`;
    tell('scroll=' + scrollbox.scrollTop);
  });
  moveZone.addEventListener('mousemove', event => {
    moveReport.textContent = `MOVE_REPORT=${event.screenX},${event.screenY}`;
    tell('move=' + event.screenX + ',' + event.screenY);
  });

  let dragEvents = [];
  const showDragEvents = () => {
    dragReport.textContent = `DRAG_REPORT=${dragEvents.join('>')}`;
    tell('drag=' + dragEvents.join('>'));
  };
  dragZone.addEventListener('mousedown', event => {
    dragEvents = ['press'];
    showDragEvents();
    event.preventDefault();
  });
  dragZone.addEventListener('mousemove', () => {
    if (dragEvents[0] === 'press' && dragEvents[dragEvents.length - 1] !== 'move') {
      dragEvents.push('move');
      showDragEvents();
    }
  });
  dragZone.addEventListener('mouseup', event => {
    if (dragEvents[0] === 'press') {
      dragEvents.push('release');
      showDragEvents();
    }
    event.preventDefault();
  });
</script>
</body>
</html>"#;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Verdict {
        DeliveredAndObserved,
        DeliveredButNotObserved,
        Refused,
        /// The target for this action never became addressable, so nothing was
        /// sent. Distinct from Refused, which means production declined a real
        /// attempt, and from DeliveredButNotObserved, which means it was sent.
        /// Neither of those is true here and claiming either would be a
        /// statement about the input path rather than about the window.
        Unmeasurable,
    }

    impl Verdict {
        fn label(self) -> &'static str {
            match self {
                Self::DeliveredAndObserved => "delivered and observed",
                Self::DeliveredButNotObserved => "delivered but not observed",
                Self::Unmeasurable => "unmeasurable: target never addressable",
                Self::Refused => "refused",
            }
        }
    }

    #[derive(Debug, Deserialize)]
    struct AxLine {
        role: String,
        name: String,
        value: Option<String>,
    }

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

        let (executable, identity) = select_browser()?;
        println!("selected browser: {}", executable.display());
        println!("browser identity: {identity}");

        let page =
            ProbePage::start().map_err(|error| format!("fixture failed to start: {error}"))?;
        println!("fixture: {}", page.url());

        let config = BrowserConfig {
            executable_path: Some(executable),
            expected_identity: Some(identity.clone()),
            launch_handshake_deadline_ms: 10_000,
            termination_grace_period_ms: 5_000,
            browser_idle_timeout_ms: 60_000,
            browser_exit_observation_deadline_ms: 5_000,
            navigation_settle_deadline_ms: 10_000,
        };
        let planes = Planes::with_browser_config_journaling(
            Arc::new(HealthState::new()),
            Some(config),
            cerebellum::JournalPersistence::Isolated,
        );
        bind_route(
            &planes,
            TOOL_CHANNEL,
            TOOL_EPOCH,
            RouteTarget::ToolProvider {
                module_id: "cerebellum".to_string(),
            },
            false,
        )
        .await?;
        bind_route(
            &planes,
            MANAGEMENT_CHANNEL,
            MANAGEMENT_EPOCH,
            RouteTarget::ManagementSurface {
                module_id: "cerebellum".to_string(),
            },
            true,
        )
        .await?;

        let launched = invoke_tool(&planes, 1, "browser.launch", json!({})).await?;
        println!("launch: {launched}");
        if launched["outcome"] != "launched" {
            return Err(format!("production launcher refused: {launched}"));
        }
        let browser_session_id = launched["browser_session_id"]
            .as_str()
            .ok_or_else(|| format!("launch did not name its browser session: {launched}"))?
            .to_string();

        let mut target = None;
        let proof = drive_after_launch(&planes, &page, &identity, &mut target).await;
        let teardown = teardown_browser(&planes, &browser_session_id, target.as_ref()).await;

        match (proof, teardown) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(proof), Ok(())) => Err(proof),
            (Ok(()), Err(teardown)) => Err(teardown),
            (Err(proof), Err(teardown)) => {
                Err(format!("{proof}; browser teardown also failed: {teardown}"))
            }
        }
    }

    async fn drive_after_launch(
        planes: &Planes,
        page: &ProbePage,
        bundle_identity: &str,
        target_slot: &mut Option<ProcessGrant>,
    ) -> Result<(), String> {
        mint_browser_grant(planes, page.origin()).await?;

        let navigated = invoke_tool(
            planes,
            2,
            "browser.navigate",
            json!({
                "url": page.url(),
                "intent": "open the synthetic input delivery probe",
                "wait": "settle",
                "severity": {"tier": 1, "credential": false, "financial": false}
            }),
        )
        .await?;
        println!("navigation: {navigated}");
        if navigated["outcome"] != "ok" {
            return Err(format!("navigation refused: {navigated}"));
        }

        let compose_target =
            mint_target_lease(planes, bundle_identity, 20, "compose target lease").await?;
        println!(
            "compose target lease: pid={} bundle_identity={} generation={} action_kind=compose",
            compose_target.pid,
            compose_target.bundle_identity,
            compose_target.process_generation_evidence
        );
        *target_slot = Some(compose_target.clone());

        let mut snapshot_corr = 100;
        let ready = snapshot_lines(planes, &mut snapshot_corr).await?;
        let initial_value = input_value(&ready).unwrap_or_else(|| "<missing textbox>".to_string());
        println!("CDP readiness: input value={initial_value:?}");

        // Every post from here on must reach a target the user is NOT looking at.
        // A freshly launched browser is frontmost, and delivery to a focused
        // application is what an ordinary global post achieves too -- so a run
        // taken in that state cannot tell the two mechanisms apart, whatever it
        // observes.
        // The control run keeps the target frontmost ON PURPOSE. Its result is
        // not a delivery measurement -- it establishes that the page's report
        // path works at all, so that zero reports in the real run means the
        // events did not arrive rather than that nothing could ever be heard.
        let control_run = std::env::var("CEREBELLUM_PROBE_KEEP_FOCUS").is_ok();
        if control_run {
            println!(
                "CONTROL RUN: target left frontmost; this measures the INSTRUMENT, not delivery"
            );
        } else {
            push_target_to_the_background();
        }
        let target_pid = compose_target.pid as i32;
        let front_before = frontmost_process_id();
        println!("frontmost before posting: {front_before:?} (target is {target_pid})");
        if !control_run && front_before == Some(target_pid) {
            return Err(format!(
                "the target is still frontmost (pid {target_pid}), so this run cannot measure \
                 UNFOCUSED delivery. Nothing is wrong with the input path; the probe could not \
                 establish the condition its claim depends on."
            ));
        }

        // Sampled THROUGHOUT rather than at the ends. A check only before and
        // after cannot see the target coming forward in between, which is how
        // two earlier runs on this desk were invalidated by an ordinary click.
        let focus_watch = {
            let flag = Arc::new(AtomicBool::new(false));
            let seen = Arc::clone(&flag);
            std::thread::spawn(move || {
                for _ in 0..600 {
                    if frontmost_process_id() == Some(target_pid) {
                        seen.store(true, Ordering::SeqCst);
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            });
            flag
        };

        let mut verdicts = Vec::new();

        let type_reply = invoke_tool(
            planes,
            30,
            "computer.type",
            json!({
                "target": "probe-input",
                "text": TYPE_TEXT
            }),
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(150)).await;
        let type_report = match snapshot_lines(planes, &mut snapshot_corr).await {
            Ok(lines) => input_value(&lines).unwrap_or_else(|| "<missing textbox>".to_string()),
            Err(error) => format!("<CDP read refused: {error}>"),
        };
        let type_agrees = type_report == TYPE_TEXT;
        let type_verdict = verdict(&type_reply, type_agrees);
        println!("\nTYPE sent: {TYPE_TEXT:?}");
        println!("TYPE production reply: {type_reply}");
        println!("TYPE page reported over CDP: {type_report:?}");
        println!("TYPE agrees: {type_agrees}");
        println!("TYPE VERDICT: {}", type_verdict.label());
        verdicts.push(("type", type_verdict));

        let keys_reply = invoke_tool(
            planes,
            31,
            "computer.keys",
            json!({
                "target": "probe-input",
                "keys": ["control", "shift", "k"]
            }),
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(150)).await;
        let keys_report =
            report_after_snapshot(planes, &mut snapshot_corr, KEY_REPORT_PREFIX).await;
        let keys_agree = keys_report == EXPECTED_CHORD;
        let keys_verdict = verdict(&keys_reply, keys_agree);
        println!("\nKEYS sent: [control, shift, k] (no Command modifier)");
        println!("KEYS production reply: {keys_reply}");
        println!("KEYS page reported over CDP: {keys_report:?}");
        println!("KEYS agrees: {keys_agree}");
        println!("KEYS VERDICT: {}", keys_verdict.label());
        verdicts.push(("keys", keys_verdict));

        // The pointer is measured by live_global_cursor, not here: pointer
        // actions are the takeover rows, which act only in a frontmost
        // application and only under the takeover grant, while this probe
        // exists to show delivery to a target that never leads.

        // A run the target led at any point proves nothing about targeting.
        if !control_run && focus_watch.load(Ordering::SeqCst) {
            return Err(
                "the target became frontmost while the sequence was posting, so these \
                 observations cannot distinguish per-process delivery from an ordinary \
                 focused post. Re-run without touching the target application."
                    .to_string(),
            );
        }
        println!(
            "\nfrontmost after posting: {:?} (target {target_pid} never led)",
            frontmost_process_id()
        );

        // Ground truth, independent of focus and of the accessibility tree.
        // If this is empty while posts returned, the events did not arrive; if
        // it is populated while the CDP readbacks came back missing, the page
        // received them and only the READING failed.
        let reports = page.reports();
        println!("\npage reported to the server ({} events):", reports.len());
        for report in &reports {
            println!("  {report}");
        }

        println!("\nSUMMARY");
        for (action, action_verdict) in &verdicts {
            println!("  {action}: {}", action_verdict.label());
        }
        if verdicts
            .iter()
            .any(|(_, item)| *item == Verdict::DeliveredButNotObserved)
        {
            println!(
                "Chromium did not expose page evidence for at least one completed post. \
                 CGEventPostToPid returning void does not establish browser receipt; this result \
                 means the production path may work for native applications without working for this browser."
            );
        }

        // A probe that measured nothing has not passed. Exiting zero here would
        // tell a reader, or a future CI step, that synthetic input was verified
        // when the only thing established is that a window never appeared. The
        // whole point of the unmeasurable verdict is to keep that distinct from
        // a refusal, so it must stay distinct in the exit code too.
        let unmeasured: Vec<&str> = verdicts
            .iter()
            .filter(|(_, item)| *item == Verdict::Unmeasurable)
            .map(|(action, _)| *action)
            .collect();
        if !unmeasured.is_empty() {
            return Err(format!(
                "nothing was measured for: {}. This is not a delivery result -- re-run with the \
                 screen unlocked before drawing any conclusion about the input path.",
                unmeasured.join(", ")
            ));
        }
        Ok(())
    }

    fn verdict(reply: &Value, observed: bool) -> Verdict {
        if reply["outcome"] != "completed" {
            Verdict::Refused
        } else if observed {
            Verdict::DeliveredAndObserved
        } else {
            Verdict::DeliveredButNotObserved
        }
    }

    async fn snapshot_lines(planes: &Planes, corr: &mut u64) -> Result<Vec<AxLine>, String> {
        let current_corr = *corr;
        *corr = corr.saturating_add(1);
        let snapshot = invoke_tool(
            planes,
            current_corr,
            "browser.snapshot",
            json!({"mode": "ax", "max_bytes": 262_144}),
        )
        .await?;
        if snapshot["outcome"] != "ok" {
            return Err(format!("browser.snapshot refused: {snapshot}"));
        }
        let content = snapshot["state_text"]
            .as_str()
            .ok_or_else(|| format!("browser.snapshot returned no content: {snapshot}"))?;
        content
            .lines()
            .map(|line| {
                serde_json::from_str(line)
                    .map_err(|error| format!("CDP AX line was not valid JSON: {error}"))
            })
            .collect()
    }

    fn input_value(lines: &[AxLine]) -> Option<String> {
        lines
            .iter()
            .find(|line| line.role == "textbox" && line.name == INPUT_LABEL)
            .and_then(|line| line.value.clone())
    }

    async fn report_after_snapshot(planes: &Planes, corr: &mut u64, prefix: &str) -> String {
        match snapshot_lines(planes, corr).await {
            Ok(lines) => report_value(&lines, prefix)
                .unwrap_or_else(|| format!("<missing page report {prefix:?}>")),
            Err(error) => format!("<CDP read refused: {error}>"),
        }
    }

    fn report_value(lines: &[AxLine], prefix: &str) -> Option<String> {
        lines
            .iter()
            .find_map(|line| line.name.strip_prefix(prefix).map(str::to_string))
    }

    /// The pid macOS currently considers frontmost, or None if it cannot say.
    fn frontmost_process_id() -> Option<i32> {
        let out = std::process::Command::new("/usr/bin/osascript")
            .args([
                "-e",
                "tell application \"System Events\" to get unix id of first process whose frontmost is true",
            ])
            .output()
            .ok()?;
        String::from_utf8_lossy(&out.stdout).trim().parse().ok()
    }

    /// Put something else in front, so the target is genuinely not frontmost.
    ///
    /// Without this the probe measures delivery to a FOCUSED application, which
    /// an ordinary global post achieves too. The whole claim of the per-process
    /// path is that it reaches a process the user is not looking at, so a run
    /// with the target in front cannot distinguish the two mechanisms and must
    /// not be reported as if it could.
    fn push_target_to_the_background() {
        let _ = std::process::Command::new("/usr/bin/open")
            .args(["-a", "Finder"])
            .status();
        std::thread::sleep(Duration::from_millis(1500));
    }

    async fn mint_browser_grant(planes: &Planes, origin: &str) -> Result<(), String> {
        let pending = answer_cards(
            planes,
            route_request(
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
            ),
            json!({"decision": "allow_30m"}),
            "browser grant",
        )
        .await?;
        if pending["outcome"] != "consent_pending" {
            return Err(format!("browser grant did not enter consent: {pending}"));
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while planes.management.browser_grant_count().await == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| "browser grant answer did not mint authority".to_string())?;
        println!("browser grant: minted through visible elicitation");
        Ok(())
    }

    async fn mint_target_lease(
        planes: &Planes,
        bundle_identity: &str,
        corr: u64,
        label: &str,
    ) -> Result<ProcessGrant, String> {
        let granted = answer_cards(
            planes,
            route_request(
                MANAGEMENT_CHANNEL,
                MANAGEMENT_EPOCH,
                corr,
                json!({
                    "method": management::OPEN_TARGET,
                    "params": {
                        "bundle_identity": bundle_identity
                    }
                }),
            ),
            json!({"decision": "allow_30m"}),
            label,
        )
        .await?;
        if granted["outcome"] != "granted" {
            return Err(format!("{label} was not granted: {granted}"));
        }
        planes
            .management
            .resolve_process(bundle_identity)
            .map_err(|refusal| format!("{label}: the granted target did not resolve: {refusal}"))
    }

    async fn teardown_browser(
        planes: &Planes,
        browser_session_id: &str,
        target: Option<&ProcessGrant>,
    ) -> Result<(), String> {
        let close = invoke_tool(
            planes,
            90,
            "browser.close",
            json!({"browser_session_id": browser_session_id}),
        )
        .await?;
        println!("close: {close}");
        let status = invoke_tool(planes, 91, "browser.status", json!({})).await?;
        println!("status after close: {status}");

        let exact_generation_running = if let Some(target) = target {
            wait_for_exact_process_exit(target, Duration::from_secs(2)).await
        } else {
            false
        };
        println!("exact launched process running after close: {exact_generation_running}");
        let clean = close["outcome"] == "closed"
            && status["outcome"] == "terminal"
            && status["terminal_outcome"] == "closed"
            && !exact_generation_running;
        println!("nothing left running: {clean}");
        if clean {
            Ok(())
        } else {
            Err(format!(
                "production teardown did not prove a clean close: close={close} status={status} exact_generation_running={exact_generation_running}"
            ))
        }
    }

    async fn wait_for_exact_process_exit(target: &ProcessGrant, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline && exact_process_is_running(target) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        exact_process_is_running(target)
    }

    fn exact_process_is_running(target: &ProcessGrant) -> bool {
        let Ok(expected) = target.process_generation_evidence.parse::<u64>() else {
            return true;
        };
        cerebellum_macos::process_start_time_micros(target.pid) == Some(expected)
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
                "effectiveCapabilityScope": ["*"],
                "browserControlOperations": [
                    "browser.launch",
                    "browser.status",
                    "browser.close"
                ]
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
        BindIdentity::new("probe", CONVERSATION.to_string())
    }

    struct ProbePage {
        address: SocketAddr,
        url: String,
        stop: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
        /// What the page reported receiving, recorded server-side.
        reports: Arc<Mutex<Vec<String>>>,
    }

    /// Decode the percent-escapes a beacon URL carries. Only the few this page
    /// can produce; anything else passes through, since a garbled report is
    /// still evidence that SOMETHING arrived.
    fn percent_decode(raw: &str) -> String {
        let bytes = raw.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'%' && index + 2 < bytes.len() {
                if let Ok(byte) = u8::from_str_radix(&raw[index + 1..index + 3], 16) {
                    out.push(byte);
                    index += 3;
                    continue;
                }
            }
            out.push(bytes[index]);
            index += 1;
        }
        String::from_utf8_lossy(&out).to_string()
    }

    impl ProbePage {
        fn start() -> std::io::Result<Self> {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            listener.set_nonblocking(true)?;
            let address = listener.local_addr()?;
            let stop = Arc::new(AtomicBool::new(false));
            let worker_stop = Arc::clone(&stop);
            let reports: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let worker_reports = Arc::clone(&reports);
            let worker = std::thread::spawn(move || {
                while !worker_stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            // Read only the request line: enough to tell a page
                            // fetch from a report, and it never blocks waiting
                            // for a body the beacon may not flush promptly.
                            // The listener is non-blocking and the accepted
                            // stream inherits that, so a read would return
                            // WouldBlock before the request line arrives and
                            // every report would be silently lost.
                            let _ = stream.set_nonblocking(false);
                            let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
                            let mut head = [0_u8; 1024];
                            let read = stream.read(&mut head).unwrap_or(0);
                            let request = String::from_utf8_lossy(&head[..read]).to_string();
                            let path = request.split_whitespace().nth(1).unwrap_or("/").to_string();
                            if let Some(query) = path.strip_prefix("/report?") {
                                let decoded = percent_decode(query);
                                if let Ok(mut held) = worker_reports.lock() {
                                    held.push(decoded);
                                }
                                let _ = stream.write_all(
                                    b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
                                );
                                let _ = stream.flush();
                                continue;
                            }
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{PAGE}",
                                PAGE.len()
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
                reports,
            })
        }

        /// What the PAGE says it received, independent of focus and of CDP.
        fn reports(&self) -> Vec<String> {
            self.reports
                .lock()
                .map(|held| held.clone())
                .unwrap_or_default()
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

    fn select_browser() -> Result<(PathBuf, String), String> {
        let windows = cerebellum_macos::enumerate_windows(Duration::from_secs(2))
            .map_err(|error| format!("browser selection could not enumerate windows: {error:?}"))?;
        let running: BTreeSet<(String, u32)> = windows
            .into_iter()
            .map(|window| (window.owner_bundle_identifier, window.owner_pid))
            .collect();
        let mut installed = Vec::new();
        for candidate in BROWSER_CANDIDATES {
            let path = PathBuf::from(candidate);
            if !path.is_file() {
                continue;
            }
            let Some(identity) = signing_identifier(&path) else {
                println!(
                    "browser candidate: {} signing_identity=unreadable",
                    path.display()
                );
                continue;
            };
            let existing_processes = running
                .iter()
                .filter(|(bundle, _)| bundle == &identity)
                .count();
            println!(
                "browser candidate: {} identity={} existing_window_owners={existing_processes}",
                path.display(),
                identity
            );
            installed.push(format!(
                "{} ({identity}, existing_window_owners={existing_processes})",
                path.display()
            ));
            if existing_processes == 0 {
                return Ok((path, identity));
            }
        }
        Err(format!(
            "no installed Chromium browser is safe to launch as a unique target; candidates: {}",
            installed.join(", ")
        ))
    }

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
}
