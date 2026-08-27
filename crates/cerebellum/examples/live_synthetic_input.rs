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

#[cfg(target_os = "macos")]
mod macos_probe {
    use std::collections::BTreeSet;
    use std::io::Write;
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use cerebellum::browser_config::BrowserConfig;
    use cerebellum::management::{self, ActionAuthority};
    use cerebellum::Planes;
    use cerebellum_computer::platform::ProcessGrant;
    use cerebellum_core::consent::ActionKind;
    use cerebellum_core::health::HealthState;
    use serde::Deserialize;
    use serde_json::{json, Value};
    use subc_protocol::session::ModuleControlRequest;
    use subc_protocol::{
        BindIdentity, Flags, Frame, FrameType, Principal, Priority, RouteTarget, PROTOCOL_VERSION,
    };
    use tokio::sync::mpsc;

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
    const MOVE_LABEL: &str = "Synthetic move zone";
    const DRAG_LABEL: &str = "Synthetic drag zone";
    const TYPE_TEXT: &str = "Cerebellum café";
    const KEY_REPORT_PREFIX: &str = "KEY_REPORT=";
    const SCROLL_REPORT_PREFIX: &str = "SCROLL_REPORT=";
    const MOVE_REPORT_PREFIX: &str = "MOVE_REPORT=";
    const DRAG_REPORT_PREFIX: &str = "DRAG_REPORT=";
    const EXPECTED_CHORD: &str = "control+shift+k";
    const SCROLL_LINES: i32 = -3;

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
  const input = document.getElementById('probe-input');
  const scrollbox = document.getElementById('scrollbox');
  const keyReport = document.getElementById('key-report');
  const scrollReport = document.getElementById('scroll-report');
  const moveReport = document.getElementById('move-report');
  const dragReport = document.getElementById('drag-report');
  const moveZone = document.getElementById('move-zone');
  const dragZone = document.getElementById('drag-zone');

  input.focus({preventScroll: true});
  document.addEventListener('keydown', event => {
    if (event.ctrlKey && event.shiftKey && !event.metaKey && event.key.toLowerCase() === 'k') {
      keyReport.textContent = 'KEY_REPORT=control+shift+k';
      event.preventDefault();
    }
  }, true);
  scrollbox.addEventListener('scroll', () => {
    scrollReport.textContent = `SCROLL_REPORT=${scrollbox.scrollTop}`;
  });
  moveZone.addEventListener('mousemove', event => {
    moveReport.textContent = `MOVE_REPORT=${event.screenX},${event.screenY}`;
  });

  let dragEvents = [];
  const showDragEvents = () => {
    dragReport.textContent = `DRAG_REPORT=${dragEvents.join('>')}`;
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
    }

    impl Verdict {
        fn label(self) -> &'static str {
            match self {
                Self::DeliveredAndObserved => "delivered and observed",
                Self::DeliveredButNotObserved => "delivered but not observed",
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

        let compose_target = mint_target_lease(
            planes,
            bundle_identity,
            ActionKind::Compose,
            20,
            "compose target lease",
        )
        .await?;
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

        let mut verdicts = Vec::new();

        let type_reply = invoke_tool(
            planes,
            30,
            "computer.type",
            json!({
                "target": "probe-input",
                "text": TYPE_TEXT,
                "replace_selection": false
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

        let scroll_before =
            report_after_snapshot(planes, &mut snapshot_corr, SCROLL_REPORT_PREFIX).await;
        let scroll_reply = invoke_tool(
            planes,
            32,
            "computer.scroll",
            json!({
                "target": "probe-scrollbox",
                "axis": "vertical",
                "amount_lines": SCROLL_LINES
            }),
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let scroll_after =
            report_after_snapshot(planes, &mut snapshot_corr, SCROLL_REPORT_PREFIX).await;
        let scroll_agrees = parse_i64(&scroll_before)
            .zip(parse_i64(&scroll_after))
            .is_some_and(|(before, after)| after > before);
        let scroll_verdict = verdict(&scroll_reply, scroll_agrees);
        println!("\nSCROLL sent: vertical {SCROLL_LINES} lines");
        println!("SCROLL production reply: {scroll_reply}");
        println!("SCROLL page reported over CDP: scrollTop {scroll_before:?} -> {scroll_after:?}");
        println!("SCROLL agrees: {scroll_agrees}");
        println!("SCROLL VERDICT: {}", scroll_verdict.label());
        verdicts.push(("scroll", scroll_verdict));

        let (move_frame, drag_frame) = wait_for_pointer_frames(compose_target.pid).await?;
        let move_point = frame_point(move_frame, 0.5, 0.5);
        let move_reply = invoke_tool(
            planes,
            33,
            "computer.move",
            json!({"to": wire_point(move_point)}),
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(150)).await;
        let move_report =
            report_after_snapshot(planes, &mut snapshot_corr, MOVE_REPORT_PREFIX).await;
        let move_agrees = parse_pair(&move_report).is_some_and(|reported| {
            (reported.0 - move_point.0).abs() <= 3.0 && (reported.1 - move_point.1).abs() <= 3.0
        });
        let move_verdict = verdict(&move_reply, move_agrees);
        println!(
            "\nMOVE sent: global point ({:.1}, {:.1}) over {MOVE_LABEL:?}",
            move_point.0, move_point.1
        );
        println!("MOVE production reply: {move_reply}");
        println!("MOVE page reported over CDP (screenX,screenY): {move_report:?}");
        println!("MOVE agrees: {move_agrees}");
        println!("MOVE VERDICT: {}", move_verdict.label());
        verdicts.push(("move", move_verdict));

        // Drag is classified mutate_durable because the same gesture could drag a file to the
        // trash. This fixture only records press/move/release and has no durable effect, so this
        // stronger lease is exceptional probe authority rather than a routine way to mint one.
        let durable_target = mint_target_lease(
            planes,
            bundle_identity,
            ActionKind::MutateDurable,
            21,
            "drag mutate_durable target lease",
        )
        .await?;
        if durable_target.pid != compose_target.pid
            || durable_target.bundle_identity != compose_target.bundle_identity
            || durable_target.process_generation_evidence
                != compose_target.process_generation_evidence
        {
            return Err(format!(
                "drag lease widened or changed target: compose={compose_target:?} durable={durable_target:?}"
            ));
        }

        let drag_from = frame_point(drag_frame, 0.25, 0.5);
        let drag_to = frame_point(drag_frame, 0.75, 0.5);
        let drag_reply = invoke_tool(
            planes,
            34,
            "computer.drag",
            json!({
                "from": wire_point(drag_from),
                "to": wire_point(drag_to),
                "button": "left",
                "modifiers": []
            }),
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let drag_report =
            report_after_snapshot(planes, &mut snapshot_corr, DRAG_REPORT_PREFIX).await;
        let drag_agrees = drag_report == "press>move>release";
        let drag_verdict = verdict(&drag_reply, drag_agrees);
        println!(
            "\nDRAG sent: ({:.1}, {:.1}) -> ({:.1}, {:.1}) over {DRAG_LABEL:?}",
            drag_from.0, drag_from.1, drag_to.0, drag_to.1
        );
        println!("DRAG production reply: {drag_reply}");
        println!("DRAG page reported over CDP: {drag_report:?}");
        println!("DRAG agrees: {drag_agrees}");
        println!(
            "DRAG VERDICT: {} (minted lease: pid={} bundle_identity={} generation={} action_kind=mutate_durable)",
            drag_verdict.label(),
            durable_target.pid,
            durable_target.bundle_identity,
            durable_target.process_generation_evidence
        );
        verdicts.push(("drag", drag_verdict));

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
        let content = snapshot["content"]
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

    fn parse_i64(value: &str) -> Option<i64> {
        value.parse().ok()
    }

    fn parse_pair(value: &str) -> Option<(f64, f64)> {
        let (x, y) = value.split_once(',')?;
        Some((x.parse().ok()?, y.parse().ok()?))
    }

    async fn wait_for_pointer_frames(
        pid: u32,
    ) -> Result<(cerebellum_macos::AxFrame, cerebellum_macos::AxFrame), String> {
        let started = Instant::now();
        let deadline = started + Duration::from_secs(10);
        let mut last = "no accessibility read completed".to_string();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let options = cerebellum_macos::AxReadOptions {
                timeout: remaining.min(cerebellum_macos::AxReadOptions::default().timeout),
                ..Default::default()
            };
            match cerebellum_macos::read_accessibility_tree(pid, options) {
                Ok(tree) => {
                    let move_frame = find_button_frame(&tree.root, MOVE_LABEL);
                    let drag_frame = find_button_frame(&tree.root, DRAG_LABEL);
                    last = format!(
                        "completeness={:?} move_frame={move_frame:?} drag_frame={drag_frame:?}",
                        tree.completeness
                    );
                    if tree.completeness == cerebellum_macos::AxTreeCompleteness::Complete {
                        if let (Some(move_frame), Some(drag_frame)) = (move_frame, drag_frame) {
                            return Ok((move_frame, drag_frame));
                        }
                    }
                }
                Err(error) => last = format!("accessibility read refused: {error:?}"),
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Err(format!(
            "pointer targets did not become addressable after {}ms: {last}",
            started.elapsed().as_millis()
        ))
    }

    fn find_button_frame(
        element: &cerebellum_macos::AxElement,
        title: &str,
    ) -> Option<cerebellum_macos::AxFrame> {
        if element.role.as_deref() == Some("AXButton") && element.title.as_deref() == Some(title) {
            return element.frame;
        }
        element
            .children
            .iter()
            .find_map(|child| find_button_frame(child, title))
    }

    fn frame_point(frame: cerebellum_macos::AxFrame, x_ratio: f64, y_ratio: f64) -> (f64, f64) {
        (
            frame.x + frame.width * x_ratio,
            frame.y + frame.height * y_ratio,
        )
    }

    fn wire_point(point: (f64, f64)) -> String {
        format!("{:.3},{:.3}", point.0, point.1)
    }

    async fn mint_browser_grant(planes: &Planes, origin: &str) -> Result<(), String> {
        let pending = elicit_and_answer(
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
            json!({"decision": "allow"}),
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
        action_kind: ActionKind,
        corr: u64,
        label: &str,
    ) -> Result<ProcessGrant, String> {
        let action_kind_wire = management::action_kind_to_wire(action_kind);
        let pending = elicit_and_answer(
            planes,
            route_request(
                MANAGEMENT_CHANNEL,
                MANAGEMENT_EPOCH,
                corr,
                json!({
                    "method": management::OPEN_TARGET,
                    "params": {
                        "bundle_identity": bundle_identity,
                        "action_kind": action_kind_wire
                    }
                }),
            ),
            json!({"decision": "allow_10_minutes"}),
            label,
        )
        .await?;
        if pending["outcome"] != "consent_pending" {
            return Err(format!("{label} did not enter consent: {pending}"));
        }

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match planes
                    .management
                    .authority_for(GRANTEE, action_kind, planes.lease_clock.as_ref())
                    .await
                {
                    ActionAuthority::Admitted(grant) => return Ok(grant),
                    ActionAuthority::Refused(_) => tokio::task::yield_now().await,
                }
            }
        })
        .await
        .map_err(|_| format!("{label} answer did not mint authority"))?
    }

    async fn elicit_and_answer(
        planes: &Planes,
        opening: Frame,
        answer_body: Value,
        label: &str,
    ) -> Result<Value, String> {
        let (writer, mut frames) = mpsc::channel(8);
        cerebellum::handle_frame_for_test(opening, &writer, planes)
            .await
            .map_err(|error| format!("{label} request failed: {error}"))?;

        let mut reply = None;
        let mut question = None;
        loop {
            let frame = tokio::time::timeout(Duration::from_secs(2), frames.recv())
                .await
                .map_err(|_| format!("{label} reply or question timed out"))?
                .ok_or_else(|| format!("{label} relay closed"))?;
            let body: Value = serde_json::from_slice(&frame.body)
                .map_err(|error| format!("{label} frame was not JSON: {error}"))?;
            if frame.header.ty == FrameType::Request {
                question = Some((frame, body));
            } else {
                reply = Some(body);
            }
            if let Some(reply) = reply.as_ref() {
                if reply["outcome"] != "consent_pending" || question.is_some() {
                    break;
                }
            }
        }
        let reply = reply.ok_or_else(|| format!("{label} returned no reply"))?;
        println!("{label} open: {reply}");
        if reply["outcome"] != "consent_pending" {
            println!("{label} elicitation: not opened for this typed outcome");
            return Ok(reply);
        }

        let (question_frame, question) =
            question.ok_or_else(|| format!("{label} returned no elicitation question"))?;
        println!("{label} question: {question}");
        println!("{label} answer: {answer_body}");

        let answer = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Response,
            Flags::new(false, Priority::Interactive, false),
            question_frame.header.channel,
            question_frame.header.epoch,
            question_frame.header.corr,
            serde_json::to_vec(&answer_body).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        cerebellum::handle_frame_for_test(answer, &writer, planes)
            .await
            .map_err(|error| format!("{label} answer failed: {error}"))?;
        Ok(reply)
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
        declares_elicitation: bool,
    ) -> Result<(), String> {
        let request = ModuleControlRequest::RouteBind {
            route_channel,
            epoch,
            target,
            identity: probe_identity(),
            principal: Some(Principal::Direct),
            consumer_capabilities: declares_elicitation.then(|| vec!["elicitation".to_string()]),
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
        BindIdentity {
            project_root: std::env::temp_dir().join("ck-live-synthetic-input"),
            harness: "probe".to_string(),
            session: CONVERSATION.to_string(),
        }
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
