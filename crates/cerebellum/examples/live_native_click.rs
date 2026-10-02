//! Ask native macOS Calculator to press one digit and prove the display changed.
//!
//! Calculator is deliberately different from the browser used by
//! `live_semantic_click`: it is a native AppKit application whose ordinary
//! buttons and display belong to the computer plane. A digit press touches no
//! file, sends no message, and persists no state, while the display's
//! accessibility value makes the effect directly observable.
//!
//! The probe preserves an existing Calculator session. It launches Calculator
//! only when absent, never clears it, and quits only the exact process generation
//! it launched.
//!
//! Run with:
//!
//! ```text
//! cargo run -p cerebellum --example live_native_click
//! ```

#[cfg(target_os = "macos")]
fn display_value_changed(before: &str, after: &str) -> Result<(), String> {
    if before == after {
        Err(format!(
            "display value did not change after AXPress: before={before:?} after={after:?}"
        ))
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("this probe drives macOS Calculator accessibility and has nothing to run here");
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

// The consent relay, shared by every probe that answers its own elicitation.
//
// Declared at the file's top level rather than inside the probe module: a
// `#[path]` on a mod nested in an inline module resolves against
// `examples/<inline-mod-name>/`, a directory that does not exist, and POSIX
// will not resolve `..` out of a missing component.
#[cfg(target_os = "macos")]
#[path = "support/consent_relay.rs"]
mod consent_relay;

#[cfg(target_os = "macos")]
mod macos_probe {
    use std::process::Command;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use cerebellum::management;
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

    use super::consent_relay::elicit_and_answer;

    use super::display_value_changed;

    const CALCULATOR_PROCESS_NAME: &str = "Calculator";
    const CALCULATOR_BUNDLE_ID: &str = "com.apple.calculator";
    const DIGIT_TITLES: &[&str] = &["7", "Seven"];
    const DIGIT_IDENTIFIERS: &[&str] = &["7", "Seven"];
    const TOOL_CHANNEL: u16 = 9;
    const TOOL_EPOCH: u32 = 3;
    const MANAGEMENT_CHANNEL: u16 = 4;
    const MANAGEMENT_EPOCH: u32 = 1;
    const GRANTEE: &str = "pj-live-native-click-probe";
    const CONVERSATION: &str = "live-native-click-probe";

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

        let calculator = ensure_calculator_running().await?;
        if calculator.launched {
            println!(
                "Calculator state: launched by probe; pid={} generation={}",
                calculator.pid, calculator.start_time_micros
            );
        } else {
            println!(
                "Calculator state: already running; pid={} generation={}; it will not be cleared or quit",
                calculator.pid, calculator.start_time_micros
            );
        }

        let proof = prove_native_click(&calculator).await;
        let teardown = teardown_calculator(&calculator).await;
        match (proof, teardown) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(proof), Ok(())) => Err(proof),
            (Ok(()), Err(teardown)) => Err(teardown),
            (Err(proof), Err(teardown)) => Err(format!(
                "{proof}; Calculator teardown also failed: {teardown}"
            )),
        }
    }

    async fn prove_native_click(calculator: &CalculatorSession) -> Result<(), String> {
        let before_tree =
            wait_for_calculator_controls(calculator.pid, Duration::from_secs(5)).await?;
        print_tree_observation("BEFORE", &before_tree);
        let display = find_display(&before_tree.root)?;
        println!(
            "resolved display: role={:?} title={:?} identifier={:?} value={:?} key={}",
            display.role,
            display.title,
            display.identifier,
            display.value,
            display.key.describe()
        );
        println!("BEFORE display value: {:?}", display.value);

        let button = find_digit_button(&before_tree.root)?;
        println!(
            "resolved element: role={:?} title={:?} identifier={:?} enabled={:?} actions={:?} frame={:?}",
            button.role,
            button.title,
            button.identifier,
            button.enabled,
            button.actions,
            button.frame
        );
        if !button.actions.iter().any(|action| action == "AXPress") {
            return Err(format!(
                "REFUSED unsupported_action: digit button does not advertise AXPress: {:?}",
                button.actions
            ));
        }

        let identifier_count = button
            .identifier
            .as_deref()
            .filter(|identifier| !identifier.is_empty())
            .map(|identifier| count_identifier(&before_tree.root, identifier))
            .unwrap_or(0);
        let role_title_count = count_role_and_title(&before_tree.root, &button.role, &button.title);
        println!(
            "address measurement: identifier={:?} matches={identifier_count}; role_and_title={{role:{:?}, title:{:?}}} matches={role_title_count}",
            button.identifier, button.role, button.title
        );

        let planes = Planes::new(Arc::new(HealthState::new()));
        bind_routes(&planes).await?;
        let target = mint_target_lease(&planes).await?;
        println!(
            "target lease: pid={} bundle_identity={} generation={}",
            target.pid, target.bundle_identity, target.process_generation_evidence
        );
        let expected_generation = calculator.start_time_micros.to_string();
        if target.pid != calculator.pid
            || target.bundle_identity != CALCULATOR_BUNDLE_ID
            || target.process_generation_evidence != expected_generation
        {
            return Err(format!(
                "REFUSED target_changed: Calculator resolved to a different process: launched_or_found={calculator:?} resolved={target:?}"
            ));
        }

        if role_title_count == 1 {
            println!(
                "address key: role_and_title {{ role: {:?}, title: {:?} }} (matches=1)",
                button.role, button.title
            );
            println!(
                "actuation layer: cerebellum-computer semantic dispatcher below the frozen wire schema"
            );
            println!("left unproven: wire computer.click cannot carry role_and_title");
            println!(
                "lower-layer wire intent: press; the macOS driver maps it to AXPress before delivery"
            );
            let outcome = dispatch_role_and_title(&planes, &target, &button).await?;
            println!("computer.click dispatcher outcome: {outcome}");
        } else if identifier_count == 1 {
            let identifier = button.identifier.as_deref().expect("counted identifier");
            println!("address key: identifier {identifier:?} (matches=1)");
            println!(
                "actuation layer: wire tool route -> computer.click handler -> semantic dispatcher -> macOS AXPress"
            );
            let outcome = invoke_tool(
                &planes,
                30,
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
        } else {
            return Err(format!(
                "REFUSED ambiguous_element_name: identifier matched {identifier_count} and role+title matched {role_title_count}; neither key uniquely addresses the digit button"
            ));
        }

        let (after_tree, after_value, elapsed, attempts) = wait_for_display_change(
            target.pid,
            &display.key,
            &display.value,
            Duration::from_secs(5),
        )
        .await?;
        print_tree_observation("AFTER", &after_tree);
        println!(
            "AFTER display value: {after_value:?} (observed {}ms after AXPress, attempts={attempts})",
            elapsed.as_millis()
        );
        display_value_changed(&display.value, &after_value)?;
        println!(
            "NATIVE CLICK VERDICT: Calculator display value changed from {:?} to {:?}",
            display.value, after_value
        );
        println!(
            "non-vacuity condition: an unchanged display value returns PROBE FAILED even when dispatch reports success"
        );
        Ok(())
    }

    #[derive(Debug)]
    struct CalculatorSession {
        launched: bool,
        pid: u32,
        start_time_micros: u64,
    }

    async fn ensure_calculator_running() -> Result<CalculatorSession, String> {
        let existing = calculator_pids()?;
        if existing.len() > 1 {
            return Err(format!(
                "REFUSED target_ambiguous: found multiple Calculator processes before launch: {existing:?}"
            ));
        }
        if let Some(&pid) = existing.first() {
            return session_for_pid(false, pid);
        }

        let status = Command::new("/usr/bin/open")
            .args(["-a", CALCULATOR_PROCESS_NAME])
            .status()
            .map_err(|error| format!("Calculator launch command failed: {error}"))?;
        if !status.success() {
            return Err(format!(
                "Calculator launch command exited with status {status}"
            ));
        }

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let pids = calculator_pids()?;
            if pids.len() == 1 {
                return session_for_pid(true, pids[0]);
            }
            if pids.len() > 1 {
                let cleanup = quit_calculator_application().await;
                return Err(format!(
                    "REFUSED target_ambiguous: launch produced multiple Calculator processes: {pids:?}; cleanup={cleanup:?}"
                ));
            }
            if Instant::now() >= deadline {
                let cleanup = quit_calculator_application().await;
                return Err(format!(
                    "Calculator launch returned but no process appeared within 5s; cleanup={cleanup:?}"
                ));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn session_for_pid(launched: bool, pid: u32) -> Result<CalculatorSession, String> {
        let start_time_micros =
            cerebellum_macos::process_start_time_micros(pid).ok_or_else(|| {
                format!(
                    "REFUSED process_identity_unavailable: no generation for Calculator pid {pid}"
                )
            })?;
        Ok(CalculatorSession {
            launched,
            pid,
            start_time_micros,
        })
    }

    fn calculator_pids() -> Result<Vec<u32>, String> {
        let output = Command::new("/usr/bin/pgrep")
            .args(["-x", CALCULATOR_PROCESS_NAME])
            .output()
            .map_err(|error| format!("could not inspect Calculator processes: {error}"))?;
        if !output.status.success() && output.status.code() != Some(1) {
            return Err(format!(
                "pgrep Calculator exited with status {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let stdout = String::from_utf8(output.stdout)
            .map_err(|error| format!("pgrep Calculator returned non-UTF-8 output: {error}"))?;
        let mut pids = stdout
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                line.trim()
                    .parse::<u32>()
                    .map_err(|error| format!("invalid Calculator pid {line:?}: {error}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        pids.sort_unstable();
        pids.dedup();
        Ok(pids)
    }

    async fn teardown_calculator(calculator: &CalculatorSession) -> Result<(), String> {
        if !calculator.launched {
            println!("Calculator teardown: skipped because it was already running");
            println!("nothing left behind by probe: true (no process was launched)");
            return Ok(());
        }
        if !exact_process_is_running(calculator) {
            println!(
                "Calculator quit request: skipped because the exact launched generation already exited or was replaced"
            );
            println!("nothing left behind by probe: true");
            return Ok(());
        }

        let quit = quit_calculator_application().await;
        println!("Calculator quit request: {quit:?}");
        let mut still_running =
            wait_for_exact_process_exit(calculator, Duration::from_secs(3)).await;
        if still_running {
            let forced =
                cerebellum_macos::terminate_exact_generation(cerebellum_macos::ProcessGeneration {
                    pid: calculator.pid,
                    start_time_micros: calculator.start_time_micros,
                });
            println!("Calculator exact-generation termination fallback: {forced:?}");
            still_running = wait_for_exact_process_exit(calculator, Duration::from_secs(2)).await;
        }
        println!("exact launched process running after quit: {still_running}");
        println!("nothing left behind by probe: {}", !still_running);
        if still_running {
            Err(
                "Calculator did not exit after graceful and exact-generation termination"
                    .to_string(),
            )
        } else {
            Ok(())
        }
    }

    async fn quit_calculator_application() -> Result<(), String> {
        let status = Command::new("/usr/bin/osascript")
            .args(["-e", "tell application id \"com.apple.calculator\" to quit"])
            .status()
            .map_err(|error| format!("Calculator quit command failed: {error}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!(
                "Calculator quit command exited with status {status}"
            ))
        }
    }

    async fn wait_for_exact_process_exit(
        calculator: &CalculatorSession,
        timeout: Duration,
    ) -> bool {
        let deadline = Instant::now() + timeout;
        while exact_process_is_running(calculator) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        exact_process_is_running(calculator)
    }

    fn exact_process_is_running(calculator: &CalculatorSession) -> bool {
        cerebellum_macos::process_start_time_micros(calculator.pid)
            == Some(calculator.start_time_micros)
    }

    async fn wait_for_calculator_controls(
        pid: u32,
        timeout: Duration,
    ) -> Result<cerebellum_macos::AxAccessibilityTree, String> {
        let started = Instant::now();
        let deadline = started + timeout;
        let mut attempts = 0usize;
        let mut last_tree = None;
        let mut last_error = None;
        loop {
            attempts += 1;
            match read_tree_once(pid) {
                Ok(tree) => {
                    let complete =
                        tree.completeness == cerebellum_macos::AxTreeCompleteness::Complete;
                    if complete && find_digit_button(&tree.root).is_ok() {
                        println!(
                            "Calculator controls became readable {}ms after process discovery (attempts={attempts})",
                            started.elapsed().as_millis()
                        );
                        return Ok(tree);
                    }
                    last_tree = Some(tree);
                }
                Err(error) => last_error = Some(error),
            }
            if Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        if let Some(tree) = last_tree {
            print_tree_observation("READ REFUSAL", &tree);
            print_unresolved_button_measurements(&tree.root);
            let diagnostics = named_value_elements(&tree.root);
            return Err(format!(
                "REFUSED element_not_found: no unique Calculator digit button appeared within {}ms (attempts={attempts}); named AXValueDescription elements={diagnostics:?}",
                started.elapsed().as_millis()
            ));
        }
        Err(format!(
            "REFUSED accessibility_read: no Calculator tree was readable within {}ms (attempts={attempts}); last refusal={}",
            started.elapsed().as_millis(),
            last_error.unwrap_or_else(|| "no read completed".to_string())
        ))
    }

    fn read_tree_once(pid: u32) -> Result<cerebellum_macos::AxAccessibilityTree, String> {
        cerebellum_macos::read_accessibility_tree(pid, cerebellum_macos::AxReadOptions::default())
            .map_err(|error| format!("{error:?}"))
    }

    fn print_tree_observation(phase: &str, tree: &cerebellum_macos::AxAccessibilityTree) {
        println!(
            "{phase} accessibility tree: completeness={:?} elements={} root_role={:?} root_children={}",
            tree.completeness,
            element_count(&tree.root),
            tree.root.role,
            tree.root.children.len()
        );
    }

    fn element_count(element: &cerebellum_macos::AxElement) -> usize {
        1 + element.children.iter().map(element_count).sum::<usize>()
    }

    #[derive(Debug, Clone)]
    struct ButtonObservation {
        role: String,
        title: String,
        identifier: Option<String>,
        enabled: Option<bool>,
        actions: Vec<String>,
        frame: Option<cerebellum_macos::AxFrame>,
    }

    fn find_digit_button(root: &cerebellum_macos::AxElement) -> Result<ButtonObservation, String> {
        let mut matches = Vec::new();
        collect_digit_buttons(root, &mut matches);
        match matches.as_slice() {
            [button] => Ok(ButtonObservation {
                role: button.role.clone().unwrap_or_default(),
                title: button.title.clone().unwrap_or_default(),
                identifier: button.identifier.clone(),
                enabled: button.enabled,
                actions: button.actions.clone(),
                frame: button.frame,
            }),
            [] => Err(format!(
                "REFUSED element_not_found: no AXButton used a supported digit title {DIGIT_TITLES:?} or identifier {DIGIT_IDENTIFIERS:?}"
            )),
            many => Err(format!(
                "REFUSED ambiguous_element_name: {} AXButtons matched the supported digit names",
                many.len()
            )),
        }
    }

    fn collect_digit_buttons<'a>(
        element: &'a cerebellum_macos::AxElement,
        matches: &mut Vec<&'a cerebellum_macos::AxElement>,
    ) {
        let is_digit = element.role.as_deref() == Some("AXButton")
            && (element
                .title
                .as_deref()
                .is_some_and(|title| DIGIT_TITLES.contains(&title))
                || element
                    .identifier
                    .as_deref()
                    .is_some_and(|identifier| DIGIT_IDENTIFIERS.contains(&identifier)));
        if is_digit {
            matches.push(element);
        }
        for child in &element.children {
            collect_digit_buttons(child, matches);
        }
    }

    fn print_unresolved_button_measurements(root: &cerebellum_macos::AxElement) {
        for title in DIGIT_TITLES {
            println!(
                "unresolved address measurement: role_and_title={{role:\"AXButton\", title:{title:?}}} matches={}",
                count_role_and_title(root, "AXButton", title)
            );
        }
        for identifier in DIGIT_IDENTIFIERS {
            println!(
                "unresolved address measurement: identifier={identifier:?} matches={}",
                count_identifier(root, identifier)
            );
        }
    }

    #[derive(Debug, Clone)]
    enum DisplayKey {
        Identifier(String),
        RoleAndTitle { role: String, title: String },
    }

    impl DisplayKey {
        fn describe(&self) -> String {
            match self {
                Self::Identifier(identifier) => format!("identifier {identifier:?}"),
                Self::RoleAndTitle { role, title } => {
                    format!("role_and_title {{ role: {role:?}, title: {title:?} }}")
                }
            }
        }
    }

    #[derive(Debug, Clone)]
    struct DisplayObservation {
        role: String,
        title: String,
        identifier: Option<String>,
        value: String,
        key: DisplayKey,
    }

    fn find_display(root: &cerebellum_macos::AxElement) -> Result<DisplayObservation, String> {
        let mut candidates = Vec::new();
        collect_value_elements(root, &mut candidates);
        let named = candidates
            .iter()
            .copied()
            .filter(|element| display_named(element))
            .collect::<Vec<_>>();
        let candidates = if named.is_empty() { candidates } else { named };
        let addressable = candidates
            .into_iter()
            .filter_map(|element| display_observation(root, element))
            .collect::<Vec<_>>();
        match addressable.as_slice() {
            [display] => Ok(display.clone()),
            [] => Err(format!(
                "REFUSED display_value_unavailable: no uniquely addressable non-control element exposed AXValueDescription; the production AxElement snapshot does not carry raw AXValue, so substituting a title would not prove the requested after-state; named AXValueDescription elements={:?}",
                named_value_elements(root)
            )),
            many => Err(format!(
                "REFUSED display_ambiguous: {} uniquely addressable elements could be Calculator's display: {:?}",
                many.len(),
                many.iter()
                    .map(|display| (&display.role, &display.title, &display.identifier, &display.value))
                    .collect::<Vec<_>>()
            )),
        }
    }

    fn collect_value_elements<'a>(
        element: &'a cerebellum_macos::AxElement,
        values: &mut Vec<&'a cerebellum_macos::AxElement>,
    ) {
        if element.role.as_deref() != Some("AXButton")
            && element
                .value_description
                .as_deref()
                .is_some_and(|value| !value.is_empty())
        {
            values.push(element);
        }
        for child in &element.children {
            collect_value_elements(child, values);
        }
    }

    fn display_named(element: &cerebellum_macos::AxElement) -> bool {
        element
            .identifier
            .as_deref()
            .into_iter()
            .chain(element.title.as_deref())
            .any(|name| name.to_ascii_lowercase().contains("display"))
    }

    fn display_observation(
        root: &cerebellum_macos::AxElement,
        element: &cerebellum_macos::AxElement,
    ) -> Option<DisplayObservation> {
        let role = element.role.clone().unwrap_or_default();
        let title = element.title.clone().unwrap_or_default();
        let identifier = element.identifier.clone().filter(|value| !value.is_empty());
        let value = element.value_description.clone()?;
        let key = identifier
            .as_deref()
            .filter(|identifier| count_identifier(root, identifier) == 1)
            .map(|identifier| DisplayKey::Identifier(identifier.to_string()))
            .or_else(|| {
                (count_role_and_title(root, &role, &title) == 1).then(|| DisplayKey::RoleAndTitle {
                    role: role.clone(),
                    title: title.clone(),
                })
            })?;
        Some(DisplayObservation {
            role,
            title,
            identifier,
            value,
            key,
        })
    }

    type NamedValueElement = (Option<String>, Option<String>, Option<String>, String);

    fn named_value_elements(root: &cerebellum_macos::AxElement) -> Vec<NamedValueElement> {
        let mut values = Vec::new();
        collect_value_elements(root, &mut values);
        values
            .into_iter()
            .map(|element| {
                (
                    element.role.clone(),
                    element.title.clone(),
                    element.identifier.clone(),
                    element.value_description.clone().unwrap_or_default(),
                )
            })
            .collect()
    }

    fn resolve_display_value(
        root: &cerebellum_macos::AxElement,
        key: &DisplayKey,
    ) -> Result<String, String> {
        let mut matches = Vec::new();
        collect_display_key(root, key, &mut matches);
        match matches.as_slice() {
            [element] => element.value_description.clone().ok_or_else(|| {
                format!(
                    "REFUSED display_value_unavailable: {} no longer exposes AXValueDescription",
                    key.describe()
                )
            }),
            many => Err(format!(
                "REFUSED display_resolution_changed: {} matched {} elements after AXPress",
                key.describe(),
                many.len()
            )),
        }
    }

    fn collect_display_key<'a>(
        element: &'a cerebellum_macos::AxElement,
        key: &DisplayKey,
        matches: &mut Vec<&'a cerebellum_macos::AxElement>,
    ) {
        let matched = match key {
            DisplayKey::Identifier(identifier) => {
                element.identifier.as_deref() == Some(identifier.as_str())
            }
            DisplayKey::RoleAndTitle { role, title } => {
                element.role.as_deref() == Some(role.as_str())
                    && element.title.as_deref().unwrap_or_default() == title
            }
        };
        if matched {
            matches.push(element);
        }
        for child in &element.children {
            collect_display_key(child, key, matches);
        }
    }

    async fn wait_for_display_change(
        pid: u32,
        key: &DisplayKey,
        before: &str,
        timeout: Duration,
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
        let deadline = started + timeout;
        let mut attempts = 0usize;
        let mut last_tree = None;
        let mut last_value = None;
        let mut last_error = None;
        loop {
            attempts += 1;
            match read_tree_once(pid) {
                Ok(tree) if tree.completeness == cerebellum_macos::AxTreeCompleteness::Complete => {
                    match resolve_display_value(&tree.root, key) {
                        Ok(value) if value != before => {
                            return Ok((tree, value, started.elapsed(), attempts));
                        }
                        Ok(value) => last_value = Some(value),
                        Err(error) => last_error = Some(error),
                    }
                    last_tree = Some(tree);
                }
                Ok(tree) => {
                    last_error = Some(format!(
                        "incomplete accessibility tree: {:?}",
                        tree.completeness
                    ));
                    last_tree = Some(tree);
                }
                Err(error) => last_error = Some(error),
            }
            if Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        if let (Some(tree), Some(value)) = (last_tree, last_value) {
            print_tree_observation("UNCHANGED", &tree);
            display_value_changed(before, &value)?;
        }
        Err(format!(
            "display change was not observable within {}ms (attempts={attempts}); last refusal={}",
            started.elapsed().as_millis(),
            last_error.unwrap_or_else(|| "display remained unchanged".to_string())
        ))
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

    async fn dispatch_role_and_title(
        planes: &Planes,
        target: &ProcessGrant,
        button: &ButtonObservation,
    ) -> Result<Value, String> {
        let current = match planes.management.resolve_process(&target.bundle_identity) {
            Ok(grant) => grant,
            Err(refusal) => {
                return Err(format!(
                    "REFUSED target_authority: authority refused before dispatch: {refusal}"
                ))
            }
        };
        if &current != target {
            return Err(format!(
                "REFUSED target_changed: target changed between tree read and dispatch: before={target:?} now={current:?}"
            ));
        }

        let mut driver = MacOs26PlatformDriver::default().without_expected_post_condition();
        let tree = driver
            .read_accessibility_tree(AccessibilityTreeRequest {
                target: current.clone(),
                settle_interval_ms: 500,
            })
            .map_err(|error| format!("REFUSED dispatcher_accessibility_read: {error:?}"))?;
        let root_identifier = tree.root_identifier.ok_or_else(|| {
            "REFUSED dispatcher_accessibility_read: no root identifier".to_string()
        })?;
        let element = driver
            .resolve_element(ElementResolutionRequest {
                root_identifier,
                element_name: AccessibilityElementName::role_and_title(
                    button.role.clone(),
                    button.title.clone(),
                ),
            })
            .map_err(|error| format!("REFUSED role_and_title_resolution: {error:?}"))?;
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
        .map_err(|error| format!("REFUSED attendance_lease: {error:?}"))?;
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
                "live-native-click-no-effect-claim-v1",
                PostCondition::ElementPresent {
                    element: element.element_name.clone(),
                },
            ),
            attendance,
            dispatch_at_ms,
        )
        .with_semantic(element, SEMANTIC_PRESS_ACTION);
        let identity = JournalIdentity {
            witness: cerebellum_core::dispatch_witness::DispatchWitness::detached(),
            principal: format!("{:?}", Principal::Direct),
            conversation_key: CONVERSATION.to_string(),
            agent_project_id: GRANTEE.to_string(),
            session_kind: SessionKind::Primary,
        };
        let mut audit = cerebellum::computer_capability::production_audit()
            .map_err(|error| format!("production audit unavailable: {error}"))?;
        let action_obligation_id = audit.journal().next_sequence();
        let probe_single_action_has_no_interrupt =
            cerebellum_computer::platform::process_event::never_cancelled;
        let report = Dispatcher::new(driver, &probe_single_action_has_no_interrupt)
            .dispatch(&mut audit, identity, request)
            .map_err(|error| {
                let typed = serde_json::to_string(&error).unwrap_or_else(|_| format!("{error:?}"));
                format!("REFUSED semantic_dispatch: {typed}")
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

    async fn mint_target_lease(planes: &Planes) -> Result<ProcessGrant, String> {
        let pending = elicit_and_answer(
            planes,
            route_request(
                MANAGEMENT_CHANNEL,
                MANAGEMENT_EPOCH,
                20,
                json!({
                    "method": management::OPEN_TARGET,
                    "params": {
                        "bundle_identity": CALCULATOR_BUNDLE_ID
                    }
                }),
            ),
            json!({"decision": "allow_conversation"}),
            "target lease",
        )
        .await?;
        if pending["outcome"] != "granted" {
            return Err(format!("target grant refused: {pending}"));
        }

        planes
            .management
            .resolve_process(CALCULATOR_BUNDLE_ID)
            .map_err(|refusal| format!("the granted target did not resolve: {refusal}"))
    }

    async fn bind_routes(planes: &Planes) -> Result<(), String> {
        bind_route(
            planes,
            TOOL_CHANNEL,
            TOOL_EPOCH,
            RouteTarget::ToolProvider {
                module_id: "cerebellum".to_string(),
            },
            false,
        )
        .await?;
        bind_route(
            planes,
            MANAGEMENT_CHANNEL,
            MANAGEMENT_EPOCH,
            RouteTarget::ManagementSurface {
                module_id: "cerebellum".to_string(),
            },
            true,
        )
        .await
    }

    async fn bind_route(
        planes: &Planes,
        route_channel: u16,
        epoch: u32,
        target: RouteTarget,
        declares_elicitation: bool,
    ) -> Result<(), String> {
        let request = ModuleControlRequest::RouteBind {
            role_versions: None,
            route_channel,
            epoch,
            target,
            identity: probe_identity(),
            principal: cerebellum::session_caller_principal_for_test(),
            consumer_capabilities: declares_elicitation.then(|| vec!["elicitation".to_string()]),
            admission_facts: Some(json!({
                "agentProjectId": GRANTEE,
                "sessionKind": "primary",
                "effectiveCapabilityScope": ["*"]
            })),
            scope: None,
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
            std::env::temp_dir().join("ck-live-native-click"),
            "probe",
            CONVERSATION.to_string(),
        )
    }
}

// The probe body these tests exercise is macOS-only, so the module is gated to
// match it. Without this the tests reference symbols that do not exist on other
// hosts, and the cross-platform lint fails for a reason unrelated to the code
// under test.
#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::display_value_changed;

    #[test]
    fn unchanged_display_value_is_a_failure() {
        let refusal = display_value_changed("42", "42").expect_err("unchanged must refuse");
        assert!(refusal.contains("did not change"));
    }

    #[test]
    fn changed_display_value_is_accepted() {
        display_value_changed("42", "427").expect("changed value proves the effect");
    }
}
