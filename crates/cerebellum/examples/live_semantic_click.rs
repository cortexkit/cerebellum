//! Press a real browser control through the macOS accessibility path and prove
//! the page changed by reading its visible text back from accessibility.
//!
//! The browser is launched and closed by the production launcher. Its only page
//! is a loopback fixture owned by this process, so the probe never presses a
//! control in an application that was already running on the user's machine.
//!
//! Run with:
//!
//! ```text
//! cargo run -p cerebellum --example live_semantic_click
//! ```

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("this probe drives macOS accessibility and has nothing to run here");
}

#[cfg(target_os = "macos")]
#[tokio::main]
async fn main() {
    if let Err(reason) = macos_probe::run().await {
        eprintln!("PROBE FAILED: {reason}");
        // A locked screen is the first thing to rule out, because its
        // signature is easy to misread as a defect in whatever the probe was
        // driving. An application LAUNCHED under a locked session appears to
        // start, answers about itself, and exposes only a menu bar: its
        // accessibility tree reports a root with one child and no AXWindow,
        // because the window was never realised. Applications launched BEFORE
        // the lock keep their full trees, which is why some targets read
        // normally in the same run and makes the cause look like a property of
        // the target rather than of the session.
        if cerebellum_macos::screen_is_locked() == Some(true) {
            eprintln!(
                "  the screen is locked. An application launched now does not \
                 realise its windows, so a menu-bar-only tree is expected and \
                 says nothing about actuation. Re-run unlocked before treating \
                 this as a defect."
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
    use cerebellum_computer::dispatch::post_condition::PostCondition;
    use cerebellum_computer::dispatch::{
        AttendanceContext, AttendanceLease, DispatchRequest, Dispatcher, ExpectedPostCondition,
        FrozenDispatchRow,
    };
    use cerebellum_computer::platform::macos::MacOs26PlatformDriver;
    use cerebellum_computer::platform::{
        AccessibilityElementName, AccessibilityTreeRequest, DispatchMode, ElementResolutionRequest,
        PlatformDriver, ProcessGrant, SEMANTIC_PRESS_ACTION,
    };
    use cerebellum_core::clock::MonotonicClock;
    use cerebellum_core::health::HealthState;
    use cerebellum_core::identity::SessionKind;
    use cerebellum_core::journal::JournalIdentity;
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
    const BUTTON_LABEL: &str = "Run semantic accessibility probe";
    const BEFORE_TEXT: &str = "Semantic click probe before";
    const AFTER_TEXT: &str = "Semantic click probe after";
    const TOOL_CHANNEL: u16 = 9;
    const TOOL_EPOCH: u32 = 3;
    const MANAGEMENT_CHANNEL: u16 = 4;
    const MANAGEMENT_EPOCH: u32 = 1;
    const GRANTEE: &str = "pj-live-semantic-click-probe";
    const CONVERSATION: &str = "live-semantic-click-probe";

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
                "intent": "open the semantic accessibility click probe",
                "wait": "settle",
                "severity": {"tier": 1, "credential": false, "financial": false}
            }),
        )
        .await?;
        println!("navigation: {navigated}");
        if navigated["outcome"] != "ok" {
            return Err(format!("navigation refused: {navigated}"));
        }
        let navigation_settled_at = Instant::now();

        let target = mint_target_lease(planes, bundle_identity).await?;
        println!(
            "target lease: pid={} bundle_identity={} generation={}",
            target.pid, target.bundle_identity, target.process_generation_evidence
        );
        *target_slot = Some(target.clone());

        let (before, button) = match wait_for_page_button(
            target.pid,
            navigation_settled_at,
            Duration::from_secs(20),
        )
        .await?
        {
            PageReadiness::Addressable {
                tree,
                button,
                elapsed,
                attempts,
            } => {
                println!(
                    "accessibility readiness: page button became addressable {}ms after navigation settled (attempts={attempts})",
                    elapsed.as_millis()
                );
                print_tree_observation("BEFORE", &tree);
                (tree, button)
            }
            PageReadiness::PageUnreachable {
                tree,
                elapsed,
                attempts,
            } => {
                println!(
                    "PAGE ACCESSIBILITY VERDICT: a complete tree still exposed no {BUTTON_LABEL:?} button {}ms after navigation settled (attempts={attempts})",
                    elapsed.as_millis()
                );
                print_tree_observation("PAGE TIMEOUT", &tree);
                return run_native_ui_fallback(planes, &target, tree).await;
            }
        };

        let before_text = exact_text(&before.root, BUTTON_LABEL)
            .ok_or_else(|| format!("BEFORE tree did not expose visible text {BUTTON_LABEL:?}"))?
            .to_string();
        println!("BEFORE visible text: {before_text:?}");
        actuate_element(planes, &target, &before, &button, 30).await?;

        let (after, after_text, effect_elapsed, attempts) =
            wait_for_exact_text(target.pid, AFTER_TEXT, Duration::from_secs(5)).await?;
        print_tree_observation("AFTER", &after);
        println!(
            "AFTER visible text: {after_text:?} (observed {}ms after click, attempts={attempts})",
            effect_elapsed.as_millis()
        );

        if before_text == after_text || before_text != BUTTON_LABEL || after_text != AFTER_TEXT {
            return Err(format!(
                "visible page text did not prove the click: before={before_text:?} after={after_text:?}"
            ));
        }
        println!(
            "CLICK VERDICT: accessibility text changed from {before_text:?} to {after_text:?}"
        );
        Ok(())
    }

    enum PageReadiness {
        Addressable {
            tree: cerebellum_macos::AxAccessibilityTree,
            button: ElementObservation,
            elapsed: Duration,
            attempts: usize,
        },
        PageUnreachable {
            tree: cerebellum_macos::AxAccessibilityTree,
            elapsed: Duration,
            attempts: usize,
        },
    }

    async fn wait_for_page_button(
        pid: u32,
        navigation_settled_at: Instant,
        maximum_wait: Duration,
    ) -> Result<PageReadiness, String> {
        let deadline = navigation_settled_at + maximum_wait;
        let mut attempts = 0usize;
        let mut last_complete = None;
        let mut last_incomplete = None;
        let mut last_error = None;

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            attempts += 1;
            match read_tree_once(
                pid,
                remaining.min(cerebellum_macos::AxReadOptions::default().timeout),
            ) {
                Ok(tree) if tree.completeness == cerebellum_macos::AxTreeCompleteness::Complete => {
                    let matches = count_role_and_title(&tree.root, "AXButton", BUTTON_LABEL);
                    if matches > 1 {
                        return Err(format!(
                            "page accessibility became available but {BUTTON_LABEL:?} matched {matches} buttons"
                        ));
                    }
                    if matches == 1 {
                        let button = find_named_button(&tree.root, BUTTON_LABEL)?;
                        return Ok(PageReadiness::Addressable {
                            tree,
                            button,
                            elapsed: navigation_settled_at.elapsed(),
                            attempts,
                        });
                    }
                    last_complete = Some(tree);
                }
                Ok(tree) => last_incomplete = Some(tree),
                Err(error) => last_error = Some(error),
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            tokio::time::sleep(remaining.min(Duration::from_millis(50))).await;
        }

        let elapsed = navigation_settled_at.elapsed();
        if let Some(tree) = last_complete {
            return Ok(PageReadiness::PageUnreachable {
                tree,
                elapsed,
                attempts,
            });
        }
        if let Some(tree) = last_incomplete {
            return Err(format!(
                "accessibility readiness deadline expired after {}ms with an incomplete tree: {:?}",
                elapsed.as_millis(),
                tree.completeness
            ));
        }
        Err(format!(
            "accessibility readiness deadline expired after {}ms without a readable tree; last refusal: {}",
            elapsed.as_millis(),
            last_error.unwrap_or_else(|| "no read completed before the deadline".to_string())
        ))
    }

    async fn wait_for_exact_text(
        pid: u32,
        expected: &str,
        maximum_wait: Duration,
    ) -> Result<
        (
            cerebellum_macos::AxAccessibilityTree,
            String,
            Duration,
            usize,
        ),
        String,
    > {
        let started = Instant::now();
        let deadline = started + maximum_wait;
        let mut attempts = 0usize;
        let mut last_observation = "no tree read completed".to_string();

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            attempts += 1;
            match read_tree_once(
                pid,
                remaining.min(cerebellum_macos::AxReadOptions::default().timeout),
            ) {
                Ok(tree) => {
                    last_observation = format!(
                        "completeness={:?}, root_children={}",
                        tree.completeness,
                        tree.root.children.len()
                    );
                    if tree.completeness == cerebellum_macos::AxTreeCompleteness::Complete {
                        if let Some(text) = exact_text(&tree.root, expected).map(str::to_string) {
                            return Ok((tree, text, started.elapsed(), attempts));
                        }
                    }
                }
                Err(error) => last_observation = error,
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            tokio::time::sleep(remaining.min(Duration::from_millis(50))).await;
        }

        Err(format!(
            "AFTER accessibility deadline expired after {}ms without exact text {expected:?}; last observation: {last_observation}",
            started.elapsed().as_millis()
        ))
    }

    async fn wait_for_window_title_change(
        pid: u32,
        before_titles: &[String],
        maximum_wait: Duration,
    ) -> Result<
        (
            cerebellum_macos::AxAccessibilityTree,
            Vec<String>,
            Duration,
            usize,
        ),
        String,
    > {
        let started = Instant::now();
        let deadline = started + maximum_wait;
        let mut attempts = 0usize;
        let mut last_titles = before_titles.to_vec();
        let mut last_observation = "no tree read completed".to_string();

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            attempts += 1;
            match read_tree_once(
                pid,
                remaining.min(cerebellum_macos::AxReadOptions::default().timeout),
            ) {
                Ok(tree) => {
                    last_observation = format!("completeness={:?}", tree.completeness);
                    if tree.completeness == cerebellum_macos::AxTreeCompleteness::Complete {
                        let titles = window_titles(&tree.root);
                        if titles.len() > before_titles.len() && titles != before_titles {
                            return Ok((tree, titles, started.elapsed(), attempts));
                        }
                        last_titles = titles;
                    }
                }
                Err(error) => last_observation = error,
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            tokio::time::sleep(remaining.min(Duration::from_millis(50))).await;
        }

        Err(format!(
            "native UI effect deadline expired after {}ms; AXWindow titles before={before_titles:?} last={last_titles:?}; last observation: {last_observation}",
            started.elapsed().as_millis()
        ))
    }

    fn read_tree_once(
        pid: u32,
        timeout: Duration,
    ) -> Result<cerebellum_macos::AxAccessibilityTree, String> {
        let options = cerebellum_macos::AxReadOptions {
            timeout,
            ..Default::default()
        };
        cerebellum_macos::read_accessibility_tree(pid, options)
            .map_err(|error| format!("accessibility read refused: {error:?}"))
    }

    fn print_tree_observation(phase: &str, tree: &cerebellum_macos::AxAccessibilityTree) {
        let options = cerebellum_macos::AxReadOptions::default();
        println!(
            "{phase} accessibility tree: completeness={:?} root_role={:?} root_children={} bounds=default(timeout={:?}, max_depth={}, max_elements={})",
            tree.completeness,
            tree.root.role,
            tree.root.children.len(),
            options.timeout,
            options.max_depth,
            options.max_elements
        );
    }

    async fn actuate_element(
        planes: &Planes,
        target: &ProcessGrant,
        tree: &cerebellum_macos::AxAccessibilityTree,
        element: &ElementObservation,
        correlation: u64,
    ) -> Result<(), String> {
        println!(
            "resolved element: role={:?} title={:?} identifier={:?} enabled={:?} actions={:?} frame={:?}",
            element.role,
            element.title,
            element.identifier,
            element.enabled,
            element.actions,
            element.frame
        );
        if !element.actions.iter().any(|action| action == "AXPress") {
            return Err(format!(
                "named element does not advertise AXPress: {:?}",
                element.actions
            ));
        }

        let identifier_count = element
            .identifier
            .as_deref()
            .filter(|identifier| !identifier.is_empty())
            .map(|identifier| count_identifier(&tree.root, identifier))
            .unwrap_or_default();
        if identifier_count == 1 {
            let identifier = element.identifier.as_deref().expect("counted identifier");
            println!("address key: identifier {identifier:?}");
            println!(
                "actuation layer: wire tool route -> computer.click handler -> semantic dispatcher -> macOS AXPress"
            );
            let outcome = invoke_tool(
                planes,
                correlation,
                "computer.click",
                json!({
                    "target": identifier,
                    "button": "left",
                    "click_count": 1,
                    "modifiers": []
                }),
            )
            .await?;
            println!("computer.click outcome: {outcome}");
            if outcome["outcome"] != "handler_returned_no_effect_claim" {
                return Err(format!("computer.click refused: {outcome}"));
            }
            return Ok(());
        }

        match element.identifier.as_deref() {
            None | Some("") => {
                println!("wire address measurement: the named element has no usable AXIdentifier")
            }
            Some(identifier) => println!(
                "wire address measurement: AXIdentifier {identifier:?} occurs {identifier_count} times"
            ),
        }
        let role_title_count = count_role_and_title(&tree.root, &element.role, &element.title);
        println!(
            "address key: role_and_title {{ role: {:?}, title: {:?} }} (matches={role_title_count})",
            element.role, element.title
        );
        if role_title_count != 1 {
            return Err(
                "neither supported accessibility key uniquely addresses the element".to_string(),
            );
        }
        println!(
            "actuation layer: cerebellum-computer semantic dispatcher below the frozen wire schema"
        );
        println!("left unproven: the wire computer.click schema cannot carry role_and_title");
        println!(
            "lower-layer wire intent: press; the macOS driver maps it to AXPress before delivery"
        );
        let outcome = dispatch_role_and_title(planes, target, element).await?;
        println!("computer.click dispatcher outcome: {outcome}");
        Ok(())
    }

    async fn run_native_ui_fallback(
        planes: &Planes,
        target: &ProcessGrant,
        before: cerebellum_macos::AxAccessibilityTree,
    ) -> Result<(), String> {
        if before.completeness != cerebellum_macos::AxTreeCompleteness::Complete {
            return Err(format!(
                "native UI fallback refused an incomplete tree: {:?}",
                before.completeness
            ));
        }
        let control = find_named_element(&before.root, "AXMenuItem", "New Window")?;
        let before_titles = window_titles(&before.root);
        println!(
            "NATIVE UI FALLBACK: selecting the browser's own {title:?} menu item because a new controlled browser window has an observable AXWindow-title effect; this proves native application UI actuation, not web-content actuation",
            title = control.title
        );
        println!("native fallback BEFORE AXWindow titles: {before_titles:?}");
        actuate_element(planes, target, &before, &control, 31).await?;

        let (after, after_titles, elapsed, attempts) =
            wait_for_window_title_change(target.pid, &before_titles, Duration::from_secs(5))
                .await?;
        print_tree_observation("NATIVE FALLBACK AFTER", &after);
        println!(
            "native fallback AFTER AXWindow titles: {after_titles:?} (observed {}ms after click, attempts={attempts})",
            elapsed.as_millis()
        );
        println!(
            "NATIVE UI FALLBACK VERDICT: exact AXWindow title list changed from {before_titles:?} to {after_titles:?}; original web-content claim remains unproven"
        );
        Ok(())
    }

    fn window_titles(root: &cerebellum_macos::AxElement) -> Vec<String> {
        fn collect(element: &cerebellum_macos::AxElement, titles: &mut Vec<String>) {
            if element.role.as_deref() == Some("AXWindow") {
                titles.push(element.title.clone().unwrap_or_default());
            }
            for child in &element.children {
                collect(child, titles);
            }
        }

        let mut titles = Vec::new();
        collect(root, &mut titles);
        titles.sort();
        titles
    }

    async fn dispatch_role_and_title(
        planes: &Planes,
        target: &ProcessGrant,
        button: &ElementObservation,
    ) -> Result<Value, String> {
        let current = match planes
            .management
            .authority_for(
                GRANTEE,
                cerebellum_core::consent::ActionKind::Compose,
                planes.lease_clock.as_ref(),
            )
            .await
        {
            ActionAuthority::Admitted(grant) => grant,
            ActionAuthority::Refused(refusal) => {
                return Err(format!(
                    "target authority refused before dispatch: {refusal}"
                ))
            }
        };
        if &current != target {
            return Err(format!(
                "target changed between accessibility read and dispatch: before={target:?} now={current:?}"
            ));
        }

        let mut driver = MacOs26PlatformDriver::default().without_expected_post_condition();
        let tree = driver
            .read_accessibility_tree(AccessibilityTreeRequest {
                target: current.clone(),
                settle_interval_ms: 500,
            })
            .map_err(|error| format!("dispatcher accessibility read refused: {error:?}"))?;
        println!(
            "dispatcher tree: {}",
            serde_json::to_string(&tree).map_err(|error| error.to_string())?
        );
        let root_identifier = tree.root_identifier.ok_or_else(|| {
            "dispatcher accessibility read returned no root identifier".to_string()
        })?;
        let element = driver
            .resolve_element(ElementResolutionRequest {
                root_identifier,
                element_name: AccessibilityElementName::role_and_title(
                    button.role.clone(),
                    button.title.clone(),
                ),
            })
            .map_err(|error| format!("role_and_title resolution refused: {error:?}"))?;
        println!(
            "dispatcher resolved: {}",
            serde_json::to_string(&element).map_err(|error| error.to_string())?
        );

        let row = FrozenDispatchRow::for_capability("computer.click")
            .ok_or_else(|| "frozen vocabulary has no computer.click row".to_string())?;
        let dispatch_at_ms = planes.lease_clock.now().as_nanos() / 1_000_000;
        let expires_at_ms = dispatch_at_ms.saturating_add(row.maximum_attendance_lease_age_ms);
        let lease = AttendanceLease::new(
            CONVERSATION,
            current.clone(),
            GRANTEE,
            dispatch_at_ms,
            expires_at_ms,
            current.process_generation_evidence.clone(),
            "cerebellum-serve-context-v1",
        )
        .map_err(|error| format!("attendance lease refused: {error:?}"))?;
        let attendance = AttendanceContext::background(
            CONVERSATION,
            current.clone(),
            GRANTEE,
            lease,
            dispatch_at_ms,
            dispatch_at_ms,
            row.maximum_attendance_lease_age_ms,
            row.maximum_attendance_check_to_dispatch_interval_ms,
            true,
        );
        let request = DispatchRequest::new(
            row,
            DispatchMode::Background,
            current,
            ExpectedPostCondition::new(
                "live-semantic-click-no-effect-claim-v1",
                PostCondition::ElementPresent {
                    element: element.element_name.clone(),
                },
            ),
            attendance,
            dispatch_at_ms,
        )
        .with_semantic(element, SEMANTIC_PRESS_ACTION);
        let identity = JournalIdentity {
            principal: format!("{:?}", Principal::Direct),
            conversation_key: CONVERSATION.to_string(),
            agent_project_id: GRANTEE.to_string(),
            session_kind: SessionKind::Primary,
        };
        let mut audit = cerebellum::computer_capability::production_audit()
            .map_err(|error| format!("production audit unavailable: {error}"))?;
        let action_obligation_id = audit.journal().next_sequence();
        let report = Dispatcher::new(driver)
            .dispatch(&mut audit, identity, request)
            .map_err(|error| {
                let typed = serde_json::to_string(&error).unwrap_or_else(|_| format!("{error:?}"));
                format!("semantic dispatcher refused: {typed}")
            })?;
        let containment_rung = report
            .containment
            .rung()
            .ok_or_else(|| "semantic dispatch returned no containment rung".to_string())?;
        let journal_rung = audit
            .read_computer_audit_record(action_obligation_id)
            .map_err(|error| format!("semantic audit record unavailable: {error:?}"))?
            .descriptor
            .containment_rung;
        let reported_rung =
            serde_json::to_value(containment_rung).map_err(|error| error.to_string())?;
        let recorded_rung =
            serde_json::to_value(journal_rung).map_err(|error| error.to_string())?;
        if reported_rung != recorded_rung {
            return Err(format!(
                "semantic containment diverged between reply and journal: reply={reported_rung} journal={recorded_rung}"
            ));
        }
        Ok(json!({
            "outcome": "dispatcher_accepted_no_effect_claim",
            "delivery_primitive": report.delivery_primitive,
            "containment_rung": reported_rung,
            "journal_containment_rung": recorded_rung,
            "accepted_by_platform": report.platform_result.accepted_by_platform,
            "effect_status": report.effect.status,
        }))
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
        println!("browser grant: minted through elicitation");
        Ok(())
    }

    async fn mint_target_lease(
        planes: &Planes,
        bundle_identity: &str,
    ) -> Result<ProcessGrant, String> {
        let pending = elicit_and_answer(
            planes,
            route_request(
                MANAGEMENT_CHANNEL,
                MANAGEMENT_EPOCH,
                20,
                json!({
                    "method": management::OPEN_TARGET,
                    "params": {
                        "bundle_identity": bundle_identity,
                        "action_kind": "compose"
                    }
                }),
            ),
            json!({"decision": "allow_10_minutes"}),
            "target lease",
        )
        .await?;
        if pending["outcome"] != "consent_pending" {
            return Err(format!("target lease did not enter consent: {pending}"));
        }

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match planes
                    .management
                    .authority_for(
                        GRANTEE,
                        cerebellum_core::consent::ActionKind::Compose,
                        planes.lease_clock.as_ref(),
                    )
                    .await
                {
                    ActionAuthority::Admitted(grant) => return Ok(grant),
                    ActionAuthority::Refused(_) => tokio::task::yield_now().await,
                }
            }
        })
        .await
        .map_err(|_| "target consent answer did not mint authority".to_string())?
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
        while exact_process_is_running(target) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        exact_process_is_running(target)
    }

    fn exact_process_is_running(target: &ProcessGrant) -> bool {
        cerebellum_macos::process_start_time_micros(target.pid)
            .map(|generation| generation.to_string())
            .as_deref()
            == Some(target.process_generation_evidence.as_str())
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
        BindIdentity::new(
            std::env::temp_dir().join("ck-live-semantic-click"),
            "probe",
            CONVERSATION.to_string(),
        )
    }

    #[derive(Debug, Clone)]
    struct ElementObservation {
        role: String,
        title: String,
        identifier: Option<String>,
        enabled: Option<bool>,
        actions: Vec<String>,
        frame: Option<cerebellum_macos::AxFrame>,
    }

    fn find_named_button(
        root: &cerebellum_macos::AxElement,
        name: &str,
    ) -> Result<ElementObservation, String> {
        find_named_element(root, "AXButton", name)
    }

    fn find_named_element(
        root: &cerebellum_macos::AxElement,
        role: &str,
        title: &str,
    ) -> Result<ElementObservation, String> {
        fn collect(
            element: &cerebellum_macos::AxElement,
            role: &str,
            title: &str,
            matches: &mut Vec<ElementObservation>,
        ) {
            if element.role.as_deref() == Some(role) && element.title.as_deref() == Some(title) {
                matches.push(ElementObservation {
                    role: element.role.clone().unwrap_or_default(),
                    title: element.title.clone().unwrap_or_default(),
                    identifier: element.identifier.clone(),
                    enabled: element.enabled,
                    actions: element.actions.clone(),
                    frame: element.frame,
                });
            }
            for child in &element.children {
                collect(child, role, title, matches);
            }
        }

        let mut matches = Vec::new();
        collect(root, role, title, &mut matches);
        match matches.len() {
            1 => Ok(matches.remove(0)),
            count => Err(format!(
                "role {role:?} and title {title:?} resolved {count} elements instead of one"
            )),
        }
    }

    fn exact_text<'a>(element: &'a cerebellum_macos::AxElement, expected: &str) -> Option<&'a str> {
        if element.title.as_deref() == Some(expected) {
            return element.title.as_deref();
        }
        if element.value_description.as_deref() == Some(expected) {
            return element.value_description.as_deref();
        }
        element
            .children
            .iter()
            .find_map(|child| exact_text(child, expected))
    }

    fn count_identifier(element: &cerebellum_macos::AxElement, identifier: &str) -> usize {
        usize::from(element.identifier.as_deref() == Some(identifier))
            + element
                .children
                .iter()
                .map(|child| count_identifier(child, identifier))
                .sum::<usize>()
    }

    fn count_role_and_title(
        element: &cerebellum_macos::AxElement,
        role: &str,
        title: &str,
    ) -> usize {
        usize::from(
            element.role.as_deref() == Some(role) && element.title.as_deref() == Some(title),
        ) + element
            .children
            .iter()
            .map(|child| count_role_and_title(child, role, title))
            .sum::<usize>()
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
                            let body = format!(
                                "<!doctype html><html><head><title>Cerebellum Semantic Click Probe</title></head>\
                                 <body><main><h1 id='status' aria-label='{BEFORE_TEXT}'>{BEFORE_TEXT}</h1>\
                                 <button type='button' aria-label='{BUTTON_LABEL}' \
                                 onclick=\"const status=document.getElementById('status');status.textContent='{AFTER_TEXT}';status.setAttribute('aria-label','{AFTER_TEXT}');this.textContent='{AFTER_TEXT}';this.setAttribute('aria-label','{AFTER_TEXT}')\">\
                                 {BUTTON_LABEL}</button></main></body></html>"
                            );
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
