//! Unsupervised, in-process desk checks. Build and unit-test this program away
//! from the desk; run it only with the operator's approval on an unlocked Mac.
//! `all` or individual arm names select live checks. No Return key is sent.
//! Missing evidence is not a PASS, including an absent refusal-ring entry.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const ARMS: &[&str] = &[
    "read_ids",
    "discord_background_read",
    "ungranted_app",
    "coordinate_covered",
    "write_text_web",
    "identity_recheck",
    "takeover_other_conversation",
    "chord_background",
    "drag_scroll",
    "cancel_mid_type",
    "consent_expiry",
    "always_grant_signers",
    "route_recorded",
    "symbol_missing",
    "auth_attach_failure",
];
const BUILD: &str = r#"Build (unreviewed probe bindings, NOT release attestations):
  source <(sed -n '/^export CEREBELLUM_/p' scripts/release-build.sh)
  export CEREBELLUM_APP_STATE_REVIEW_REVISION=desk-unreviewed/v13
  export CEREBELLUM_ELEMENT_ADDRESSED_REVIEW_REVISION=desk-unreviewed/v13
  export CEREBELLUM_TAKEOVER_DISPATCH_REVIEW_REVISION=desk-unreviewed/v13
  export CEREBELLUM_PRIVATE_INPUT_ROUTE_REVIEW_REVISION=desk-unreviewed/v13
  CARGO_TARGET_DIR=target/probe-arms cargo build --locked -p cerebellum --example v13_desk_arms
Run with fresh directories (never point these variables at the live module):
  scratch=$(mktemp -d /tmp/ck-v13.XXXXXX)
  mkdir "$scratch/data" "$scratch/config" "$scratch/runtime"
  XDG_DATA_HOME="$scratch/data" XDG_CONFIG_HOME="$scratch/config" XDG_RUNTIME_DIR="$scratch/runtime" target/probe-arms/debug/examples/v13_desk_arms all
TextEdit must have no open documents. Discord must already show an EMPTY Message @… composer.
Finder must have an existing window. Its bounds and the original frontmost app are restored.
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Pass,
    Fail,
    Unmeasurable,
}
impl Verdict {
    fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Unmeasurable => "UNMEASURABLE",
        }
    }
}
fn exit_code(verdicts: &[Verdict]) -> i32 {
    if !verdicts.is_empty() && verdicts.iter().all(|v| *v == Verdict::Pass) {
        0
    } else {
        1
    }
}
const REQUIRED_CAPABILITIES: &[&str] = &[
    "computer.read_state",
    "computer.press_element",
    "computer.press_point",
    "computer.write_text",
    "computer.type",
    "computer.keys",
    "computer.takeover_drag",
    "computer.takeover_scroll",
];
fn build_ready(advertised: &[String], private: bool) -> bool {
    private
        && REQUIRED_CAPABILITIES
            .iter()
            .all(|required| advertised.iter().any(|actual| actual == required))
}
fn selected(args: impl Iterator<Item = String>) -> Result<Vec<String>, String> {
    let args: Vec<_> = args.collect();
    if args == ["all"] {
        return Ok(ARMS.iter().map(|s| s.to_string()).collect());
    }
    if args.is_empty() || args.iter().any(|s| !ARMS.contains(&s.as_str())) {
        return Err(format!("select all or one or more of {}", ARMS.join(", ")));
    }
    let mut result = Vec::new();
    for arg in args {
        if !result.contains(&arg) {
            result.push(arg);
        }
    }
    Ok(result)
}

// Inputs are already canonicalized. Restricting scratch roots to /tmp also
// excludes an operator's custom data home elsewhere in their home directory.
fn guard_paths(
    roots: &[PathBuf],
    real_home: &Path,
    tmp: &Path,
    locked: bool,
) -> Result<(), String> {
    if locked {
        return Err("screen is locked".into());
    }
    if roots.len() != 3 {
        return Err("all three XDG roots must be set".into());
    }
    for root in roots {
        if root.starts_with(real_home) || !root.starts_with(tmp) || root == tmp {
            return Err(format!(
                "not an isolated /tmp scratch root: {}",
                root.display()
            ));
        }
    }
    if roots.iter().enumerate().any(|(i, a)| {
        roots
            .iter()
            .skip(i + 1)
            .any(|b| a.starts_with(b) || b.starts_with(a))
    }) {
        return Err("XDG roots must be distinct, non-nested directories".into());
    }
    Ok(())
}

fn decode_bytes(value: &Value) -> Result<Vec<u8>, String> {
    if let Some(text) = value.as_str() {
        cerebellum_core::serde_base64::decode(text).map_err(str::to_string)
    } else {
        serde_json::from_value(value.clone()).map_err(|e| format!("invalid byte array: {e}"))
    }
}
fn decode_payloads(value: &mut Value) -> Result<(), String> {
    if let Some(object) = value.as_object_mut() {
        for (key, child) in object {
            if matches!(
                key.as_str(),
                "bytes"
                    | "completed_result"
                    | "dispatch_material"
                    | "grant_decision"
                    | "invocation_descriptor"
                    | "final_context"
                    | "governing_observation"
                    | "rejection_material"
            ) && !child.is_null()
            {
                let bytes = decode_bytes(child)?;
                *child = if bytes.is_empty() {
                    json!([])
                } else {
                    serde_json::from_slice(&bytes).map_err(|e| format!("{key}: {e}"))?
                };
            }
            decode_payloads(child)?;
        }
    } else if let Some(array) = value.as_array_mut() {
        for child in array {
            decode_payloads(child)?;
        }
    }
    Ok(())
}
fn decode_journal(bytes: &[u8]) -> Result<BTreeMap<String, Value>, String> {
    let mut file: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if file["schema_version"] != 2 {
        return Err("unexpected journal schema".into());
    }
    let state = file["state"].as_object_mut().ok_or("missing state")?;
    let mut rows = BTreeMap::new();
    for kind in ["entries", "reservations"] {
        let entries = state
            .get_mut(kind)
            .and_then(Value::as_object_mut)
            .ok_or("missing journal map")?;
        for (sequence, row) in entries {
            decode_payloads(row)?;
            rows.insert(format!("{kind}/{sequence}"), row.clone());
        }
    }
    Ok(rows)
}
fn contains_fact(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(s) => s == expected,
        Value::Object(o) => o.values().any(|v| contains_fact(v, expected)),
        Value::Array(a) => a.iter().any(|v| contains_fact(v, expected)),
        _ => false,
    }
}
fn fields_named<'a>(
    value: &'a Value,
    name: &str,
    path: &str,
    found: &mut Vec<(String, &'a Value)>,
) {
    match value {
        Value::Object(o) => {
            for (key, child) in o {
                let next = format!("{path}/{key}");
                if key == name {
                    found.push((next.clone(), child));
                }
                fields_named(child, name, &next, found);
            }
        }
        Value::Array(a) => {
            for (i, child) in a.iter().enumerate() {
                fields_named(child, name, &format!("{path}/{i}"), found);
            }
        }
        _ => (),
    }
}
fn read_state_facts(row: &Value) -> Result<(), String> {
    for name in [
        "manual_accessibility",
        "element_count",
        "unreadable_subtrees",
        "image_returned",
    ] {
        let mut found = Vec::new();
        fields_named(row, name, "", &mut found);
        if found.len() != 1 {
            return Err(format!(
                "expected exactly one {name}, found {}",
                found.len()
            ));
        }
        let (path, value) = &found[0];
        println!("READ FACT {path}={value}");
        let valid = match name {
            "manual_accessibility" => {
                matches!(value.as_str(), Some("newly_enabled" | "already_enabled"))
            }
            "element_count" => value.as_u64().is_some_and(|n| n > 0),
            "unreadable_subtrees" => value.as_u64().is_some(),
            "image_returned" => **value == false,
            _ => false,
        };
        if !valid {
            return Err(format!("invalid Discord read fact {path}={value}"));
        }
    }
    Ok(())
}
fn tree_labels(tree: &str) -> Result<Vec<String>, String> {
    let mut labels = Vec::new();
    for line in tree.lines() {
        let Some(start) = line.find('"') else {
            continue;
        };
        let mut escaped = false;
        let mut end = None;
        for (i, c) in line[start + 1..].char_indices() {
            if escaped {
                escaped = false;
                continue;
            }
            if c == '\\' {
                escaped = true;
            } else if c == '"' {
                end = Some(start + 1 + i);
                break;
            }
        }
        let end = end.ok_or("unterminated tree label")?;
        let label: String = serde_json::from_str(&line[start..=end])
            .map_err(|e| format!("unreadable tree label: {e}"))?;
        if !label.is_empty() {
            labels.push(label);
        }
    }
    Ok(labels)
}
fn no_screen_text(row: &Value, reply: &Value) -> Result<(), String> {
    let tree = reply["tree"].as_str().ok_or("read has no tree")?;
    let labels = tree_labels(tree)?;
    let witness = labels
        .iter()
        .find(|s| s.starts_with("Message @"))
        .ok_or("no composer label privacy witness")?;
    let wire = serde_json::to_string(reply).map_err(|e| e.to_string())?;
    let escaped = serde_json::to_string(witness).map_err(|e| e.to_string())?;
    // The tree is itself a JSON string on the wire. Check its encoded label
    // before trusting a scan of the separately decoded journal strings.
    let wire_witness = serde_json::to_string(&escaped).map_err(|e| e.to_string())?;
    if !wire.contains(&wire_witness[1..wire_witness.len() - 1]) {
        return Err("privacy witness absent from actual reply".into());
    }
    let serialized = serde_json::to_string(row).map_err(|e| e.to_string())?;
    for label in &labels {
        let needle = serde_json::to_string(label).map_err(|e| e.to_string())?;
        if serialized.contains(&needle) {
            return Err(format!("screen label leaked into journal: {label:?}"));
        }
    }
    if serialized.contains(&escaped[1..escaped.len() - 1]) {
        return Err("composer label embedded in journal".into());
    }
    println!("PRIVACY witness_present_in_reply=true quoted_labels_checked={} composer_absent_from_row=true",labels.len());
    Ok(())
}
fn route_count(value: &Value, route: &str) -> Option<u64> {
    if let Some(n) = value
        .get("routes")
        .and_then(|v| v.get(route))
        .and_then(Value::as_u64)
    {
        return Some(n);
    }
    match value {
        Value::Object(o) => o.values().find_map(|v| route_count(v, route)),
        Value::Array(a) => a.iter().find_map(|v| route_count(v, route)),
        _ => None,
    }
}
fn zero_post_evidence(rows: &BTreeMap<String, Value>, before: &Value, after: &Value) -> bool {
    // Refusals belong to the refusal ring, not the authorized-dispatch journal.
    // Even an unresolved reservation prevents a claim that nothing proceeded.
    rows.is_empty() && !before.is_null() && before == after
}

#[cfg(target_os = "macos")]
#[path = "support/consent_relay.rs"]
#[allow(dead_code)] // This probe uses the question-observing variant of the shared relay.
mod consent_relay;

#[cfg(target_os = "macos")]
mod desk {
    use super::*;
    use cerebellum::management::{PlatformResolver, TargetResolver};
    use cerebellum::Planes;
    use cerebellum_computer::platform::{native::resolve_target, ProcessGrant, TargetResolution};
    use cerebellum_core::health::HealthState;
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use subc_protocol::session::ModuleControlRequest;
    use subc_protocol::{
        BindIdentity, Flags, Frame, FrameType, Principal, Priority, RouteTarget, PROTOCOL_VERSION,
    };
    use tokio::sync::mpsc;

    const TEXT: &str = "com.apple.TextEdit";
    const DISCORD: &str = "com.hnc.Discord";
    const FINDER: &str = "com.apple.finder";
    const CONTENT: &str = "CortexKit scratch desk check. Nothing in this document is user data.\n";

    #[link(name = "ApplicationServices", kind = "framework")]
    unsafe extern "C" {
        fn CGEventSourceKeyState(state: i32, key: u16) -> bool;
        fn CGEventSourceFlagsState(state: i32) -> u64;
    }
    fn held_state() -> Value {
        let tables: Vec<_> = [-1, 0, 1].into_iter().map(|table| {
            // CoreGraphics accepts these public state-table ids; no event is posted.
            let keys: Vec<_> = (0..128).filter(|key| unsafe { CGEventSourceKeyState(table, *key) }).collect();
            let flags = unsafe { CGEventSourceFlagsState(table) };
            json!({"table":table, "keys":keys, "flags":flags, "held_modifiers":flags & 0x1e0000})
        }).collect();
        json!(tables)
    }
    fn nothing_held(state: &Value) -> bool {
        state.as_array().is_some_and(|a| {
            a.iter()
                .all(|s| s["keys"] == json!([]) && s["held_modifiers"] == 0)
        })
    }

    fn command(program: &str, args: &[&str], seconds: u64) -> Result<String, String> {
        // Drain pipes concurrently: a noisy codesign must not deadlock the timeout.
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;
        let stdout = child.stdout.take().ok_or("no stdout")?;
        let stderr = child.stderr.take().ok_or("no stderr")?;
        let read = |mut pipe: Box<dyn std::io::Read + Send>| {
            let mut s = String::new();
            let _ = pipe.read_to_string(&mut s);
            s
        };
        let out = std::thread::spawn(move || read(Box::new(stdout)));
        let err = std::thread::spawn(move || read(Box::new(stderr)));
        let start = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                break status;
            }
            if start.elapsed() > Duration::from_secs(seconds) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{program} timed out after {seconds}s"));
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let output = out.join().map_err(|_| "stdout reader panicked")?;
        let error = err.join().map_err(|_| "stderr reader panicked")?;
        if !status.success() {
            return Err(format!("{program}: {status}: {error}"));
        }
        Ok(output.trim().to_string())
    }
    fn script(code: &str) -> Result<String, String> {
        command("/usr/bin/osascript", &["-e", code], 10)
    }
    fn quote(s: &str) -> String {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    }
    fn resolve(app: &str) -> Result<ProcessGrant, String> {
        match resolve_target(app, Duration::from_secs(3)) {
            TargetResolution::Resolved(grant) => Ok(grant),
            other => Err(format!("cannot uniquely resolve {app}: {other:?}")),
        }
    }
    fn identity(app: &str) -> Result<Value, String> {
        let grant = resolve(app)?;
        let code = PlatformResolver::new()
            .app_code(&grant)
            .identity()
            .map_err(|e| format!("{e:?}"))?;
        Ok(
            json!({"pid":grant.pid,"bundle_identity":app,"team_id":code.team_id,"apple_anchored":code.apple_anchored,"ad_hoc":code.ad_hoc,"designated_requirement":code.designated_requirement}),
        )
    }
    fn snapshot(app: &str) -> Result<Value, String> {
        use cerebellum_macos::{AxStateElement, AxStateValue};
        fn elements(nodes: &[AxStateElement]) -> Value {
            json!(nodes.iter().map(|n| {
                let value = match &n.value {
                    AxStateValue::Text(s) => json!(s), AxStateValue::Boolean(b) => json!(b),
                    AxStateValue::Number(n) => json!(n), AxStateValue::Absent => Value::Null,
                    AxStateValue::Other => json!("<unreadable value>"),
                };
                json!({"role":n.role,"title":n.title,"description":n.description,"value":value,"selected":n.selected,"focused":n.focused,"children":elements(&n.children)})
            }).collect::<Vec<_>>())
        }
        let grant = resolve(app)?;
        let raw = cerebellum_macos::read_app_state(
            grant.pid,
            cerebellum_macos::AxAppStateBounds {
                max_elements: 8000,
                max_depth: 80,
                timeout: Duration::from_secs(3),
            },
        )
        .map_err(|e| format!("snapshot {app}: {e:?}"))?;
        if raw.bound_reached || raw.unreadable_subtrees != 0 {
            return Err(format!(
                "UNMEASURABLE: incomplete independent AX snapshot of {app}"
            ));
        }
        Ok(elements(&raw.roots))
    }
    fn selected_text() -> Result<String, String> {
        script("tell application \"System Events\" to tell process \"TextEdit\" to get value of attribute \"AXSelectedText\" of text area 1 of scroll area 1 of window 1")
    }
    fn scrollbar() -> Result<String, String> {
        script("tell application \"System Events\" to tell process \"TextEdit\" to get value of scroll bar 1 of scroll area 1 of window 1")
    }
    fn editor_focus() -> Result<(), String> {
        script("tell application \"TextEdit\" to activate")?;
        script("tell application \"System Events\" to tell process \"TextEdit\" to set value of attribute \"AXFocused\" of text area 1 of scroll area 1 of window 1 to true")?;
        Ok(())
    }
    fn front(app: &str) -> Result<(), String> {
        script(&format!("tell application id {} to activate", quote(app)))?;
        Ok(())
    }

    struct Fixture {
        root: PathBuf,
        document: PathBuf,
        finder_bounds: String,
        finder_id: u64,
        front_pid: Option<i32>,
        owned: bool,
    }
    impl Fixture {
        fn new(root: &Path) -> Result<Self, String> {
            // Refuse rather than close, replace, save or even read user documents.
            if script("application \"TextEdit\" is running")? == "true"
                && script("tell application \"TextEdit\" to count documents")? != "0"
            {
                return Err(
                    "TextEdit has open documents; close them yourself before running".into(),
                );
            }
            let finder_id: u64 =
                script("tell application \"Finder\" to get id of front Finder window")?
                    .parse()
                    .map_err(|_| "Finder window id unreadable")?;
            let finder_bounds = script(&format!(
                "tell application \"Finder\" to get bounds of Finder window id {finder_id}"
            ))?;
            let mut fixture = Self {
                root: root.to_path_buf(),
                document: root.join("desk.txt"),
                finder_bounds,
                finder_id,
                front_pid: cerebellum_macos::frontmost_process_id(),
                owned: false,
            };
            std::fs::write(&fixture.document, CONTENT.repeat(180)).map_err(|e| e.to_string())?;
            fixture.open("/System/Applications/TextEdit.app")?;
            Ok(fixture)
        }
        fn open(&mut self, app: &str) -> Result<(), String> {
            command(
                "/usr/bin/open",
                &[
                    "-a",
                    app,
                    self.document.to_str().ok_or("non UTF-8 scratch path")?,
                ],
                10,
            )?;
            self.owned = true;
            std::thread::sleep(Duration::from_secs(1));
            self.assert_owned()?;
            script(
                "tell application \"TextEdit\" to set bounds of front window to {80, 80, 720, 560}",
            )?;
            editor_focus()
        }
        fn assert_owned(&self) -> Result<(), String> {
            let paths = script("tell application \"TextEdit\" to get path of every document")?;
            let count = script("tell application \"TextEdit\" to count documents")?;
            if count != "1" || paths != self.document.to_string_lossy() {
                return Err(format!(
                    "TextEdit is no longer scratch-only: document count={count}; refusing changes"
                ));
            }
            Ok(())
        }
        fn close_owned(&mut self) -> Result<(), String> {
            self.assert_owned()?;
            script("tell application \"TextEdit\" to close front document saving no")?;
            self.owned = false;
            Ok(())
        }
        fn switch(&mut self, app: &str) -> Result<(), String> {
            self.close_owned()?;
            if script("tell application \"TextEdit\" to count documents")? != "0" {
                return Err("new user document appeared; not quitting TextEdit".into());
            }
            script("tell application \"TextEdit\" to quit")?;
            std::thread::sleep(Duration::from_millis(500));
            self.open(app)
        }
        fn copy_signed(&self) -> Result<PathBuf, String> {
            let copy = self.root.join("TextEdit-adhoc.app");
            if !copy.exists() {
                command(
                    "/usr/bin/ditto",
                    &[
                        "/System/Applications/TextEdit.app",
                        copy.to_str().ok_or("copy path")?,
                    ],
                    30,
                )?;
                let canonical = std::fs::canonicalize(&copy).map_err(|e| e.to_string())?;
                if !canonical.starts_with(&self.root) {
                    return Err("copy escaped scratch root".into());
                }
                command(
                    "/usr/bin/codesign",
                    &["-s", "-", "--force", canonical.to_str().ok_or("copy path")?],
                    30,
                )?;
            }
            Ok(copy)
        }
        fn reset(&self) -> Result<(), String> {
            self.assert_owned()?;
            script(&format!(
                "tell application \"TextEdit\" to set text of front document to {}",
                quote(&CONTENT.repeat(180))
            ))?;
            editor_focus()
        }
        fn restore_finder(&self) -> Result<(), String> {
            script(&format!(
                "tell application \"Finder\" to set bounds of Finder window id {} to {{{}}}",
                self.finder_id, self.finder_bounds
            ))?;
            Ok(())
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if self.owned {
                if let Err(e) = self.close_owned() {
                    eprintln!("CLEANUP FAILED: {e}");
                }
            }
            if let Err(e) = self.restore_finder() {
                eprintln!("CLEANUP FAILED: {e}");
            }
            if let Some(pid) = self.front_pid {
                let _ = script(&format!("tell application \"System Events\" to set frontmost of first application process whose unix id is {pid} to true"));
            }
        }
    }

    fn frame(channel: u16, corr: u64, body: Value) -> Frame {
        Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            channel,
            if channel == 0 { 0 } else { 1 },
            corr,
            serde_json::to_vec(&body).unwrap(),
        )
        .unwrap()
    }
    struct Probe {
        planes: Planes,
        journal: PathBuf,
        channel: u16,
        corr: u64,
        project: String,
    }
    struct Call {
        method: String,
        reply: Value,
        rows: BTreeMap<String, Value>,
        questions: Vec<Value>,
        ring: Value,
        ring_before: Value,
    }
    impl Probe {
        async fn new(journal: PathBuf) -> Result<Self, String> {
            let mut probe = Self {
                planes: Planes::new(Arc::new(HealthState::new())),
                journal,
                channel: 1,
                corr: 100,
                project: format!("desk-arms-{}", std::process::id()),
            };
            if let Err(error) = &probe.planes.computer {
                return Err(format!("computer plane unavailable: {error:?}"));
            }
            probe.conversation("initial").await?;
            Ok(probe)
        }
        async fn conversation(&mut self, name: &str) -> Result<(), String> {
            self.channel += 2;
            for (channel, target) in [
                (
                    self.channel,
                    RouteTarget::ToolProvider {
                        module_id: "cerebellum".into(),
                    },
                ),
                (
                    self.channel + 1,
                    RouteTarget::ManagementSurface {
                        module_id: "cerebellum".into(),
                    },
                ),
            ] {
                let request = ModuleControlRequest::RouteBind {
                    route_channel: channel,
                    epoch: 1,
                    target,
                    identity: BindIdentity::new(
                        "/tmp/ck-v13",
                        "probe",
                        format!("{}-{name}", self.project),
                    ),
                    principal: Some(Principal::Direct),
                    consumer_capabilities: Some(vec!["elicitation".into()]),
                    admission_facts: Some(
                        json!({"agentProjectId":self.project,"sessionKind":"primary","effectiveCapabilityScope":["*"]}),
                    ),
                };
                let (writer, mut replies) = mpsc::channel(2);
                cerebellum::handle_control_request_for_test_with_bindings(
                    frame(
                        0,
                        u64::from(channel),
                        serde_json::to_value(request).unwrap(),
                    ),
                    &writer,
                    &self.planes.health,
                    &self.planes.routes,
                )
                .await
                .map_err(|e| e.to_string())?;
                let response = tokio::time::timeout(Duration::from_secs(5), replies.recv())
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or("no bind reply")?;
                if response.header.ty != FrameType::Response {
                    return Err(format!("route bind: {:?}", response.body));
                }
            }
            Ok(())
        }
        fn journal(&self) -> Result<BTreeMap<String, Value>, String> {
            match std::fs::read(&self.journal) {
                Ok(bytes) => decode_journal(&bytes),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
                Err(e) => Err(e.to_string()),
            }
        }
        async fn ring(&self) -> Value {
            serde_json::to_value(
                self.planes
                    .computer
                    .as_ref()
                    .expect("computer plane checked at startup")
                    .refusal_history_for_test(&self.project)
                    .await,
            )
            .unwrap()
        }
        async fn call(&mut self, method: &str, args: Value, answer: &str) -> Result<Call, String> {
            let before = self.journal()?;
            let ring_before = self.ring().await;
            self.corr += 1;
            let management = method == "computer.open_target";
            let body = if management {
                json!({"method":method,"params":args})
            } else {
                json!({"name":method,"arguments":args})
            };
            let mut questions = Vec::new();
            let reply = super::consent_relay::elicit_and_answer_observing(
                &self.planes,
                frame(self.channel + u16::from(management), self.corr, body),
                json!({"decision":answer}),
                method,
                |q| questions.push(q.clone()),
            )
            .await?;
            let rows = self
                .journal()?
                .into_iter()
                .filter(|(key, value)| before.get(key) != Some(value))
                .collect();
            let call = Call {
                method: method.to_string(),
                reply,
                rows,
                questions,
                ring: self.ring().await,
                ring_before,
            };
            println!(
                "EVIDENCE {}",
                json!({"method":method,"corr":self.corr,"reply":call.reply,"journal_rows":call.rows,"refusal_ring":call.ring,"questions":call.questions})
            );
            Ok(call)
        }
        async fn grant(&mut self, app: &str) -> Result<(), String> {
            let c = self
                .call(
                    "computer.open_target",
                    json!({"bundle_identity":app}),
                    "allow_conversation",
                )
                .await?;
            if c.reply["outcome"] != "granted" {
                return Err(format!("app grant refused: {}", c.reply));
            }
            Ok(())
        }
        async fn read(&mut self, app: &str, image: bool) -> Result<Call, String> {
            self.call(
                "computer.read_state",
                json!({"target":app,"include_image":image}),
                "allow_conversation",
            )
            .await
        }
        async fn takeover(&mut self) -> Result<(), String> {
            // A scroll inside scratch TextEdit obtains the real conversation grant.
            editor_focus()?;
            tokio::time::sleep(Duration::from_secs(2)).await;
            let c = self
                .call(
                    "computer.takeover_scroll",
                    json!({"target":TEXT,"axis":"vertical","amount_lines":1}),
                    "allow_conversation",
                )
                .await?;
            if c.reply["outcome"] != "completed" {
                return Err(format!("takeover setup refused: {}", c.reply));
            }
            Ok(())
        }
    }
    fn check(ok: bool, why: &str) -> Result<(), String> {
        if ok {
            Ok(())
        } else {
            Err(why.into())
        }
    }
    fn authorized(c: &Call, code: &str, fact: Option<&str>) -> Result<(), String> {
        check(c.reply["outcome"] == code, "unexpected reply code")?;
        let capability = c.method.strip_prefix("computer.").unwrap_or(&c.method);
        check(
            c.rows.iter().any(|(key, row)| {
                key.starts_with("entries/")
                    && row["bytes"]["phase"] == "finalized"
                    && contains_fact(&row["invocation_descriptor"], capability)
            }),
            "missing finalized decoded journal row for this capability",
        )?;
        if let Some(fact) = fact {
            check(
                c.rows.values().any(|v| contains_fact(v, fact)),
                &format!("journal lacks {fact}"),
            )?;
        }
        Ok(())
    }
    fn refused(c: &Call, code: &str, before: &Value, after: &Value) -> Result<(), String> {
        println!(
            "ZERO-POST {}",
            json!({"journal_rows":c.rows,"target_before":before,"target_after":after,"unchanged":before==after,"no_actuation_row":c.rows.is_empty()})
        );
        check(c.reply["outcome"] == code, "unexpected refusal code")?;
        check(
            zero_post_evidence(&c.rows, before, after),
            "refusal posted or target changed",
        )?;
        check(
            c.ring != c.ring_before && contains_fact(&c.ring, code),
            "missing fresh refusal-ring entry with named code",
        )
    }
    fn element(reply: &Value, needle: &str) -> Result<String, String> {
        let tree = reply["tree"].as_str().ok_or("no tree")?;
        let matches: Vec<_> = tree
            .lines()
            .filter(|line| line.contains(needle))
            .filter_map(|line| {
                let word = line.split_whitespace().next()?;
                let id = word.trim_matches(|c: char| c == '[' || c == ']' || c == ':');
                (id.starts_with('e') && id[1..].chars().all(|c| c.is_ascii_digit()))
                    .then(|| id.to_string())
            })
            .collect();
        if matches.len() != 1 {
            return Err(format!(
                "need exactly one {needle:?} element, found {}",
                matches.len()
            ));
        }
        Ok(matches[0].clone())
    }
    fn image_point(c: &Call, x: u64, y: u64) -> Result<Value, String> {
        let image = &c.reply["image"];
        let id = image["image_id"]
            .as_str()
            .ok_or("image unavailable (Screen Recording permission required)")?;
        check(
            image["width_px"].as_u64().is_some_and(|w| w > x)
                && image["height_px"].as_u64().is_some_and(|h| h > y),
            "scratch image too small",
        )?;
        Ok(json!({"image_id":id,"x":x,"y":y}))
    }
    fn composer(snapshot: &Value) -> Result<&Value, String> {
        fn visit<'a>(v: &'a Value, out: &mut Vec<&'a Value>) {
            if v["role"] == "AXTextArea"
                && ["title", "description"]
                    .iter()
                    .any(|key| v[*key].as_str().is_some_and(|s| s.starts_with("Message @")))
            {
                out.push(v);
            }
            if let Some(o) = v.as_object() {
                for child in o.values() {
                    visit(child, out);
                }
            }
            if let Some(a) = v.as_array() {
                for child in a {
                    visit(child, out);
                }
            }
        }
        let mut found = Vec::new();
        visit(snapshot, &mut found);
        if found.len() != 1 {
            return Err(
                "UNMEASURABLE: no unique Discord Message @ composer in independent AX read".into(),
            );
        }
        Ok(found[0])
    }
    fn composer_empty(snapshot: &Value) -> bool {
        composer(snapshot).is_ok_and(|c| c["value"] == "")
    }

    async fn arm(name: &str, p: &mut Probe, f: &mut Fixture) -> Result<(), String> {
        p.project = format!("desk-arms-{}-{name}", std::process::id());
        p.conversation(name).await?;
        match name {
            // app_state: authorized reads must have their own finalized journal
            // row even when the caller does not request an image.
            "read_ids" => {
                f.close_owned()?;
                f.open("/System/Applications/TextEdit.app")?;
                let read = p.read(TEXT, false).await?;
                let close_lines: Vec<_> = read.reply["tree"]
                    .as_str()
                    .ok_or("no tree")?
                    .lines()
                    .filter(|line| {
                        let lower = line.to_lowercase();
                        lower.contains("button") && lower.contains("close")
                    })
                    .collect();
                check(
                    close_lines.len() == 1,
                    "need one scratch-window Close button",
                )?;
                let id = element(&json!({"tree":close_lines[0]}), "")?;
                let pressed = p
                    .call(
                        "computer.press_element",
                        json!({"element_id":id}),
                        "allow_conversation",
                    )
                    .await?;
                check(
                    script("tell application \"TextEdit\" to count documents")? == "0",
                    "press_element did not close the scratch document",
                )?;
                f.owned = false;
                p.read(TEXT, false).await?;
                f.open("/System/Applications/TextEdit.app")?;
                p.read(TEXT, false).await?;
                let before = snapshot(TEXT)?;
                let stale = p
                    .call("computer.press_element", json!({"element_id":id}), "deny")
                    .await?;
                let after = snapshot(TEXT)?;
                authorized(&read, "completed", None)?;
                authorized(&pressed, "completed", None)?;
                refused(&stale, "stale_element", &before, &after)
            }
            // app_state: Discord's web tree must be readable behind Finder.
            "discord_background_read" => {
                p.grant(DISCORD).await?;
                front(FINDER)?;
                let c = p.read(DISCORD, false).await?;
                check(
                    cerebellum_macos::frontmost_process_id() != Some(resolve(DISCORD)?.pid as i32),
                    "Discord was not background",
                )?;
                element(&c.reply, "Message @")?;
                authorized(&c, "completed", None)?;
                let rows: Vec<_> = c
                    .rows
                    .iter()
                    .filter(|(key, row)| {
                        key.starts_with("entries/")
                            && row["invocation_descriptor"]["capability"] == "read_state"
                            && row["bytes"]["phase"] == "finalized"
                    })
                    .collect();
                check(rows.len() == 1, "expected one finalized read_state row")?;
                read_state_facts(rows[0].1)?;
                no_screen_text(rows[0].1, &c.reply)
            }
            // app_state: a remembered deny must block a read before dispatch.
            "ungranted_app" => {
                let before = snapshot(TEXT)?;
                p.call(
                    "computer.open_target",
                    json!({"bundle_identity":TEXT}),
                    "deny",
                )
                .await?;
                let c = p
                    .call("computer.read_state", json!({"target":TEXT}), "deny")
                    .await?;
                refused(&c, "consent_denied", &before, &snapshot(TEXT)?)
            }
            // element_addressed: the covered coordinate must not reach Finder.
            "coordinate_covered" => {
                f.reset()?;
                let read = p.read(TEXT, true).await?;
                // Overlap title bars, not Finder's file icons: a misrouted
                // action must not open an operator document.
                let point = image_point(&read, 400, 20)?;
                script(&format!("tell application \"Finder\" to set bounds of Finder window id {} to {{80, 80, 720, 560}}", f.finder_id))?;
                front(FINDER)?;
                let before = json!({"finder":snapshot(FINDER)?,"textedit":snapshot(TEXT)?});
                let c = p
                    .call("computer.press_point", point, "allow_conversation")
                    .await?;
                let after = json!({"finder":snapshot(FINDER)?,"textedit":snapshot(TEXT)?});
                f.restore_finder()?;
                refused(&c, "target_not_frontmost", &before, &after)
            }
            // element_addressed: AX writes to a web composer are refused.
            "write_text_web" => {
                p.grant(DISCORD).await?;
                let c = p.read(DISCORD, false).await?;
                let id = element(&c.reply, "Message @")?;
                let before = snapshot(DISCORD)?;
                check(
                    composer_empty(&before),
                    "Discord composer must be empty; refusing to overwrite a draft",
                )?;
                let result=p.call("computer.write_text",json!({"element_id":id,"text":"ck-v13-unsent","write_mode":"replace_value"}),"deny").await?;
                let after = snapshot(DISCORD)?;
                if !composer_empty(&after) {
                    clear_discord(p).await?;
                }
                refused(&result, "web_content_needs_type", &before, &after)
            }
            // element_addressed: a changed signature must ask again, never reuse
            // the original grant. Denying that new question must dispatch nothing.
            "identity_recheck" => {
                p.grant(TEXT).await?;
                println!("ORIGINAL IDENTITY {}", identity(TEXT)?);
                let copy = f.copy_signed()?;
                f.switch(copy.to_str().ok_or("copy path")?)?;
                let result = async {
                    let checked = identity(TEXT)?;
                    println!("CHECKED IDENTITY {checked}");
                    check(
                        checked["ad_hoc"] == true,
                        "UNMEASURABLE: the re-signed copy is not the resolved running process",
                    )?;
                    let before = snapshot(TEXT)?;
                    let c = p
                        .call("computer.read_state", json!({"target":TEXT}), "deny")
                        .await?;
                    check(
                        c.questions.iter().any(|q| {
                            q["params"]["message"]
                                .as_str()
                                .is_some_and(|s| s.contains("signature has changed"))
                        }),
                        "no signature_changed re-consent question",
                    )?;
                    refused(&c, "consent_denied", &before, &snapshot(TEXT)?)
                }
                .await;
                f.switch("/System/Applications/TextEdit.app")?;
                result
            }
            // takeover_dispatch: conversation B must obtain its own takeover.
            "takeover_other_conversation" => {
                f.reset()?;
                p.grant(TEXT).await?;
                p.takeover().await?;
                p.conversation("takeover-B").await?;
                p.grant(TEXT).await?;
                front(FINDER)?;
                let before = snapshot(TEXT)?;
                let c = p
                    .call(
                        "computer.keys",
                        json!({"target":TEXT,"keys":["command","a"]}),
                        "deny",
                    )
                    .await?;
                check(
                    !c.questions.is_empty()
                        || c.reply["outcome"] == "modifier_chord_needs_foreground",
                    "conversation A takeover leaked into B",
                )?;
                let code = if c.reply["outcome"] == "consent_denied" {
                    "consent_denied"
                } else {
                    "modifier_chord_needs_foreground"
                };
                refused(&c, code, &before, &snapshot(TEXT)?)
            }
            // takeover_dispatch: background Cmd+A refuses without takeover,
            // then the real selected text, not the reply, proves delivery.
            "chord_background" => {
                f.reset()?;
                p.grant(TEXT).await?;
                front(FINDER)?;
                let before = snapshot(TEXT)?;
                let no = p
                    .call(
                        "computer.keys",
                        json!({"target":TEXT,"keys":["command","a"]}),
                        "deny",
                    )
                    .await?;
                let after = snapshot(TEXT)?;
                p.takeover().await?;
                front(FINDER)?;
                tokio::time::sleep(Duration::from_secs(2)).await;
                let yes = p
                    .call(
                        "computer.keys",
                        json!({"target":TEXT,"keys":["command","a"]}),
                        "allow_conversation",
                    )
                    .await?;
                let selection = selected_text()?;
                println!("SELECTED_TEXT {}", json!(selection));
                authorized(&yes, "delivery_unconfirmed", None)?;
                check(
                    selection == CONTENT.repeat(180).trim(),
                    "Cmd+A did not select all scratch text",
                )?;
                refused(&no, "modifier_chord_needs_foreground", &before, &after)
            }
            // takeover_dispatch: independently read selection and scrollbar;
            // a successful dispatch without a visible effect is insufficient.
            "drag_scroll" => {
                f.reset()?;
                p.grant(TEXT).await?;
                p.takeover().await?;
                let read = p.read(TEXT, true).await?;
                let point = image_point(&read, 180, 150)?;
                let selection = selected_text()?;
                tokio::time::sleep(Duration::from_secs(2)).await;
                let drag=p.call("computer.takeover_drag",json!({"image_id":point["image_id"],"from":{"x":40,"y":100},"to":{"x":180,"y":150}}),"allow_conversation").await?;
                let selected = selected_text()?;
                let scroll_before = scrollbar()?;
                tokio::time::sleep(Duration::from_secs(2)).await;
                let scroll = p
                    .call(
                        "computer.takeover_scroll",
                        json!({"target":TEXT,"axis":"vertical","amount_lines":30}),
                        "allow_conversation",
                    )
                    .await?;
                let scroll_after = scrollbar()?;
                println!(
                    "READBACK {}",
                    json!({"selection_before":selection,"selection_after":selected,"scroll_before":scroll_before,"scroll_after":scroll_after})
                );
                authorized(&drag, "completed", None)?;
                authorized(&scroll, "completed", None)?;
                check(
                    !selected.is_empty() && selected != selection && scroll_before != scroll_after,
                    "drag/scroll effect not observed",
                )
            }
            // takeover_dispatch: interrupt a real in-flight type, then query the
            // OS key tables and flags, never the driver's inferred held state.
            "cancel_mid_type" => cancel_type(p, f).await,
            // takeover_dispatch: both lasting signer forms and the ad-hoc
            // negative control must be observed; TextEdit cannot stand in for Discord.
            "always_grant_signers" => signers(p, f).await,
            // private_input_route: the decoded dispatch row must name SkyLight.
            "route_recorded" => {
                p.grant(DISCORD).await?;
                let read = p.read(DISCORD, false).await?;
                let id = element(&read.reply, "Message @")?;
                check(
                    composer_empty(&snapshot(DISCORD)?),
                    "Discord composer must be empty",
                )?;
                p.call(
                    "computer.press_element",
                    json!({"element_id":id}),
                    "allow_conversation",
                )
                .await?;
                check(
                    composer(&snapshot(DISCORD)?)?["focused"] == true,
                    "composer did not gain focus; not typing",
                )?;
                front(FINDER)?;
                check(
                    cerebellum_macos::frontmost_process_id() != Some(resolve(DISCORD)?.pid as i32),
                    "Discord is not background",
                )?;
                let result = p
                    .call(
                        "computer.type",
                        json!({"target":DISCORD,"text":"ck-v13-unsent"}),
                        "allow_conversation",
                    )
                    .await;
                let after = snapshot(DISCORD);
                let cleanup = clear_discord(p).await;
                let c = result?;
                let after = after?;
                cleanup?;
                println!("DISCORD READBACK {after}");
                check(
                    composer(&after)?["value"] == "ck-v13-unsent",
                    "typed text not observed in composer",
                )?;
                authorized(&c, "completed", None)?;
                check(
                    c.rows
                        .values()
                        .any(|r| route_count(r, "skylight").is_some_and(|n| n > 0)),
                    "journal has no SkyLight posts",
                )
            }
            _ => Err("unknown arm".into()),
        }
    }
    async fn clear_discord(p: &mut Probe) -> Result<(), String> {
        // This function is called only after observing an empty composer before
        // typing. It never sends Return and never clears a pre-existing draft.
        let initial = snapshot(DISCORD)?;
        let value = composer(&initial)?["value"]
            .as_str()
            .ok_or("Discord composer value unavailable")?;
        if value.is_empty() {
            return Ok(());
        }
        check(
            "ck-v13-unsent".starts_with(value),
            "Discord contains non-probe text; leaving it untouched",
        )?;
        front(DISCORD)?;
        if composer(&snapshot(DISCORD)?)?["focused"] != true {
            let read = p.read(DISCORD, false).await?;
            let id = element(&read.reply, "Message @")?;
            p.call(
                "computer.press_element",
                json!({"element_id":id}),
                "allow_conversation",
            )
            .await?;
        }
        let focused = snapshot(DISCORD)?;
        check(
            composer(&focused)?["focused"] == true && composer(&focused)?["value"] == value,
            "refusing cleanup: composer focus or value changed",
        )?;
        for keys in [json!(["command", "a"]), json!(["backspace"])] {
            let c = p
                .call(
                    "computer.keys",
                    json!({"target":DISCORD,"keys":keys}),
                    "allow_conversation",
                )
                .await?;
            check(
                matches!(
                    c.reply["outcome"].as_str(),
                    Some("completed" | "delivery_unconfirmed")
                ),
                "Discord cleanup key refused",
            )?;
        }
        check(
            composer_empty(&snapshot(DISCORD)?),
            "Discord scratch text cleanup failed",
        )
    }
    async fn cancel_type(p: &mut Probe, f: &Fixture) -> Result<(), String> {
        f.reset()?;
        script("tell application \"TextEdit\" to set text of front document to \"\"")?;
        p.grant(TEXT).await?;
        let before = held_state();
        println!("KEY STATE BEFORE {before}");
        check(
            nothing_held(&before),
            "keys/modifiers already held before cancel test",
        )?;
        let rows = p.journal()?;
        p.corr += 1;
        let (writer, mut frames) = mpsc::channel(8);
        cerebellum::handle_frame_for_test(
            frame(
                p.channel,
                p.corr,
                json!({"name":"computer.type","arguments":{"target":TEXT,"text":"x".repeat(4096)}}),
            ),
            &writer,
            &p.planes,
        )
        .await
        .map_err(|e| e.to_string())?;
        // Observe real text before cancelling so a pre-dispatch cancellation
        // cannot masquerade as recovery from an interrupted key stream.
        let start = Instant::now();
        let mut observed_chars = 0;
        while start.elapsed() < Duration::from_secs(3) {
            observed_chars = script("tell application \"TextEdit\" to get text of front document")?
                .chars()
                .count();
            if observed_chars > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        println!("CANCEL POINT observed_chars={observed_chars}");
        let cancel = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Cancel,
            Flags::new(false, Priority::Interactive, false),
            p.channel,
            1,
            p.corr,
            Vec::new(),
        )
        .map_err(|e| e.to_string())?;
        cerebellum::handle_frame_for_test(cancel, &writer, &p.planes)
            .await
            .map_err(|e| e.to_string())?;
        let response = tokio::time::timeout(Duration::from_secs(10), frames.recv())
            .await
            .map_err(|e| e.to_string())?
            .ok_or("no cancelled reply")?;
        let reply: Value = serde_json::from_slice(&response.body).map_err(|e| e.to_string())?;
        let state = held_state();
        let new_rows: BTreeMap<_, _> = p
            .journal()?
            .into_iter()
            .filter(|(k, v)| rows.get(k) != Some(v))
            .collect();
        println!(
            "CANCEL EVIDENCE {}",
            json!({"reply":reply,"journal_rows":new_rows,"real_key_state":state})
        );
        check(
            observed_chars > 0 && observed_chars < 4096,
            "did not observe a partially delivered type before cancellation",
        )?;
        check(
            reply["outcome"] == "cancelled",
            "type finished before cancellation or did not cancel",
        )?;
        check(!new_rows.is_empty(), "cancel has no journal row")?;
        check(
            nothing_held(&state),
            "real OS key/modifier state remained held",
        )
    }
    async fn signers(p: &mut Probe, f: &mut Fixture) -> Result<(), String> {
        for app in [TEXT, DISCORD] {
            let id = identity(app)?;
            println!("SIGNER {id}");
            if app == DISCORD {
                check(
                    id["team_id"].as_str().is_some_and(|s| !s.is_empty()),
                    "UNMEASURABLE: Discord Team ID unavailable",
                )?;
            } else {
                check(
                    id["apple_anchored"] == true && id["team_id"].is_null(),
                    "TextEdit must be Apple-anchored with no Team ID",
                )?;
            }
            let c = p
                .call(
                    "computer.open_target",
                    json!({"bundle_identity":app}),
                    "allow_always",
                )
                .await?;
            check(
                c.reply["outcome"] == "granted"
                    && c.reply["grant_persisted"] == true
                    && c.questions
                        .iter()
                        .any(|q| contains_fact(&q["params"]["requestedSchema"], "allow_always")),
                "lasting signer was not offered/allowed always",
            )?;
        }
        let copy = f.copy_signed()?;
        f.switch(copy.to_str().ok_or("copy path")?)?;
        let result = async {
            let id = identity(TEXT)?;
            println!("SIGNER {id}");
            check(id["ad_hoc"] == true, "copy is not ad-hoc")?;
            let before = snapshot(TEXT)?;
            let c = p
                .call(
                    "computer.open_target",
                    json!({"bundle_identity":TEXT}),
                    "allow_always",
                )
                .await?;
            let after = snapshot(TEXT)?;
            check(
                !c.questions.is_empty()
                    && c.questions.iter().all(|q| {
                        !contains_fact(&q["params"]["requestedSchema"], "allow_always")
                            && contains_fact(&q["params"]["requestedSchema"], "allow_conversation")
                    }),
                "ad-hoc choices were wrong",
            )?;
            refused(&c, "consent_unavailable", &before, &after)
        }
        .await;
        f.switch("/System/Applications/TextEdit.app")?;
        result
    }

    fn unavailable(name: &str) -> Option<&'static str> {
        match name {
            // private_input_route: native resolution has no example-only
            // override. Do not add a release runtime bypass for fault injection.
            "symbol_missing" | "auth_attach_failure" => Some("no example-only native route forcing seam; unit fences cover this fault"),
            // takeover_dispatch: the park-limit seam is not a question deadline
            // and is not exposed through the production Planes entry points.
            "consent_expiry" => Some("no Planes question-deadline seam: app deadline 1800s, takeover 300s; park limit 120s is not expiry"),
            _ => None,
        }
    }
    async fn run_selected(arms: Vec<String>, scratch: PathBuf, journal: PathBuf) -> i32 {
        let mut setup = None;
        let mut setup_reason = String::new();
        if arms.iter().any(|name| unavailable(name).is_none()) {
            match Fixture::new(&scratch) {
                Ok(fixture) => match Probe::new(journal).await {
                    Ok(probe) => setup = Some((fixture, probe)),
                    Err(e) => setup_reason = e,
                },
                Err(e) => setup_reason = e,
            }
        }
        let mut table = Vec::new();
        let mut verdicts = Vec::new();
        for name in arms {
            let (verdict, reason) = if let Some(reason) = unavailable(&name) {
                (Verdict::Unmeasurable, reason.to_string())
            } else if let Some((fixture, probe)) = setup.as_mut() {
                match arm(&name, probe, fixture).await {
                    Ok(()) => (
                        Verdict::Pass,
                        "live reply and readback checks matched".to_string(),
                    ),
                    Err(e)
                        if e.contains("UNMEASURABLE")
                            || e.starts_with("cannot uniquely resolve") =>
                    {
                        (Verdict::Unmeasurable, e)
                    }
                    Err(e) => (Verdict::Fail, e),
                }
            } else {
                (
                    Verdict::Unmeasurable,
                    format!("setup unavailable: {setup_reason}"),
                )
            };
            println!("ARM {name}: {} {reason}", verdict.label());
            verdicts.push(verdict);
            table.push((name, verdict, reason));
        }
        if let Some((fixture, _)) = setup.as_mut() {
            let cleanup = fixture.close_owned().and_then(|_| fixture.restore_finder()).and_then(|_| {
                if let Some(pid) = fixture.front_pid {
                    script(&format!("tell application \"System Events\" to set frontmost of first application process whose unix id is {pid} to true"))?;
                }
                Ok(())
            });
            if let Err(e) = cleanup {
                eprintln!("ARM cleanup: FAIL {e}");
                verdicts.push(Verdict::Fail);
            }
        }
        println!("\nARM                              VERDICT       EVIDENCE");
        for (name, verdict, reason) in table {
            println!("{name:<32} {:<13} {reason}", verdict.label());
        }
        exit_code(&verdicts)
    }
    pub fn run() -> i32 {
        // No Planes, grant store, journal, or application is opened before this.
        let guard = (|| -> Result<(PathBuf, PathBuf), String> {
            let user = command("/usr/bin/id", &["-un"], 3)?;
            let home = command(
                "/usr/bin/dscl",
                &[".", "-read", &format!("/Users/{user}"), "NFSHomeDirectory"],
                3,
            )?;
            let home = home
                .strip_prefix("NFSHomeDirectory: ")
                .ok_or("cannot read real account home")?;
            let home = std::fs::canonicalize(home).map_err(|e| e.to_string())?;
            let roots: Vec<_> = ["XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR"]
                .into_iter()
                .map(|key| {
                    let path = std::env::var_os(key).ok_or_else(|| format!("{key} is unset"))?;
                    std::fs::canonicalize(path).map_err(|e| format!("{key}: {e}"))
                })
                .collect::<Result<_, _>>()?;
            let tmp = std::fs::canonicalize("/tmp").map_err(|e| e.to_string())?;
            guard_paths(
                &roots,
                &home,
                &tmp,
                cerebellum_macos::screen_is_locked().unwrap_or(true),
            )?;
            for root in &roots {
                if std::fs::read_dir(root)
                    .map_err(|e| e.to_string())?
                    .next()
                    .is_some()
                {
                    return Err(format!(
                        "scratch directory is not empty: {}",
                        root.display()
                    ));
                }
            }
            let path = cerebellum_core::journal::journal_data_path("computer.json")
                .map_err(|e| format!("{e:?}"))?;
            let expected = roots[0].join("cortexkit/cerebellum/journal/computer.json");
            // XDG may spell /tmp as a symlink; canonicalize its existing root.
            let data_root = PathBuf::from(std::env::var_os("XDG_DATA_HOME").unwrap());
            let relative = path
                .strip_prefix(&data_root)
                .map_err(|_| "production journal escaped XDG_DATA_HOME")?;
            check(
                relative == Path::new("cortexkit/cerebellum/journal/computer.json"),
                "unexpected production journal suffix",
            )?;
            let resolved = roots[0].join(relative);
            check(
                resolved == expected
                    && path.ends_with("cortexkit/cerebellum/journal/computer.json"),
                "production journal does not resolve under scratch data home",
            )?;
            println!("SCRATCH JOURNAL {}", resolved.display());
            Ok((roots[2].clone(), resolved))
        })();
        let (scratch, journal) = match guard {
            Ok(v) => v,
            Err(e) => {
                eprintln!("ARM environment: UNMEASURABLE {e}\n{BUILD}");
                return 2;
            }
        };
        println!("{BUILD}");
        let arms = match selected(std::env::args().skip(1)) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("{e}");
                return 2;
            }
        };
        let evidence =
            cerebellum::computer_release_evidence(&cerebellum::default_computer_context());
        println!("BUILD ADVERTISEMENT {evidence:?}");
        let private = cerebellum_computer::platform::input_route::private_route_review_bound();
        println!("PRIVATE INPUT ROUTE BOUND {private}");
        if !build_ready(&evidence.advertised_capabilities, private) {
            eprintln!("ARM build: UNMEASURABLE this build lacks the four required review bindings or a required advertised capability");
            return 2;
        }
        let runtime = match tokio::runtime::Runtime::new() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("UNMEASURABLE {e}");
                return 2;
            }
        };
        runtime.block_on(run_selected(arms, scratch, journal))
    }
}

fn main() {
    #[cfg(target_os = "macos")]
    std::process::exit(desk::run());
    #[cfg(not(target_os = "macos"))]
    {
        eprintln!("UNMEASURABLE: macOS desk required\n{BUILD}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_review_binding_refuses_execution() {
        let mut advertised: Vec<String> = REQUIRED_CAPABILITIES
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(build_ready(&advertised, true));
        assert!(!build_ready(&advertised, false));
        advertised.remove(0);
        assert!(!build_ready(&advertised, true));
    }
    #[test]
    fn real_data_home_refuses() {
        let home = Path::new("/Users/operator");
        let tmp = Path::new("/private/tmp");
        let mut roots = vec![
            tmp.join("probe/data"),
            tmp.join("probe/config"),
            tmp.join("probe/runtime"),
        ];
        assert!(guard_paths(&roots, home, tmp, false).is_ok());
        roots[0] = home.join("Library/Application Support");
        assert!(guard_paths(&roots, home, tmp, false).is_err());
        roots[0] = home.join(".local/share");
        assert!(guard_paths(&roots, home, tmp, false).is_err());
    }
    #[test]
    fn locked_missing_and_nested_roots_refuse() {
        let roots = vec![
            PathBuf::from("/private/tmp/a"),
            PathBuf::from("/private/tmp/b"),
            PathBuf::from("/private/tmp/c"),
        ];
        let h = Path::new("/Users/operator");
        let t = Path::new("/private/tmp");
        assert!(guard_paths(&roots, h, t, true).is_err());
        assert!(guard_paths(&roots[..2], h, t, false).is_err());
        let mut nested = roots;
        nested[1] = nested[0].join("child");
        assert!(guard_paths(&nested, h, t, false).is_err());
    }
    #[test]
    fn only_all_pass_exits_zero() {
        assert_eq!(exit_code(&[Verdict::Pass, Verdict::Pass]), 0);
        assert_eq!(exit_code(&[]), 1);
        assert_eq!(exit_code(&[Verdict::Pass, Verdict::Fail]), 1);
        assert_eq!(exit_code(&[Verdict::Unmeasurable]), 1);
        assert_eq!(Verdict::Unmeasurable.label(), "UNMEASURABLE");
    }
    #[test]
    fn journal_decodes_stored_bytes_and_routes() {
        let payload=br#"{"completed_result":[123,34,114,111,117,116,101,115,34,58,123,34,115,107,121,108,105,103,104,116,34,58,50,44,34,112,117,98,108,105,99,34,58,48,125,125]}"#;
        let file = json!({"schema_version":2,"state":{"entries":{"7":{"bytes":cerebellum_core::serde_base64::encode(payload)}},"reservations":{}}});
        let rows = decode_journal(&serde_json::to_vec(&file).unwrap()).unwrap();
        assert_eq!(
            rows["entries/7"]["bytes"]["completed_result"],
            json!({"routes":{"skylight":2,"public":0}})
        );
        assert_eq!(route_count(&rows["entries/7"], "skylight"), Some(2));
        assert!(decode_journal(
            br#"{"schema_version":2,"state":{"entries":{"1":{"bytes":"bad!"}},"reservations":{}}}"#
        )
        .is_err());
    }
    #[test]
    fn zero_posts_requires_no_row_and_unchanged_observed_target() {
        let empty = BTreeMap::new();
        let target = json!({"text":"same"});
        assert!(zero_post_evidence(&empty, &target, &target));
        assert!(!zero_post_evidence(
            &empty,
            &target,
            &json!({"text":"changed"})
        ));
        assert!(!zero_post_evidence(&empty, &Value::Null, &Value::Null));
        let rows = BTreeMap::from([(
            "entries/1".into(),
            json!({"routes":{"skylight":0,"public":0}}),
        )]);
        assert!(!zero_post_evidence(&rows, &target, &target));
    }
    #[test]
    fn read_facts_require_unique_observed_values() {
        let good = json!({"completed_result":{"manual_accessibility":"already_enabled","element_count":27,"unreadable_subtrees":0,"image_returned":false}});
        assert!(read_state_facts(&good).is_ok());
        let mut bad = good.clone();
        bad["completed_result"]["manual_accessibility"] = json!("failed");
        assert!(read_state_facts(&bad).is_err());
        let mut missing = good.clone();
        missing["completed_result"]
            .as_object_mut()
            .unwrap()
            .remove("element_count");
        assert!(read_state_facts(&missing).is_err());
        let mut duplicate = good;
        duplicate["element_count"] = json!(27);
        assert!(read_state_facts(&duplicate).is_err());
    }
    #[test]
    fn privacy_scan_detects_screen_text_and_requires_a_reply_witness() {
        let reply = json!({"tree":"e1 text area \"Message @desk-fixture\"\ne2 text \"private fixture text\""});
        assert!(no_screen_text(&json!({"element_count":2}), &reply).is_ok());
        assert!(
            no_screen_text(&json!({"accidental_title":"Message @desk-fixture"}), &reply).is_err()
        );
        assert!(
            no_screen_text(&json!({"accidental_value":"private fixture text"}), &reply).is_err()
        );
        assert!(no_screen_text(&json!({}), &json!({"tree":""})).is_err());
    }
    #[test]
    fn empty_opaque_context_decodes_without_inventing_a_fact() {
        let encoded=serde_json::to_vec(&json!({"completed_result":serde_json::to_vec(&json!({"outcome":"handler_returned"})).unwrap(),"final_context":[]})).unwrap();
        let file = json!({"schema_version":2,"state":{"entries":{"1":{"bytes":cerebellum_core::serde_base64::encode(&encoded)}},"reservations":{}}});
        let rows = decode_journal(&serde_json::to_vec(&file).unwrap()).unwrap();
        assert_eq!(rows["entries/1"]["bytes"]["final_context"], json!([]));
        assert_eq!(route_count(&rows["entries/1"], "skylight"), None);
    }
    #[test]
    fn names_are_explicit_and_all_expands() {
        assert_eq!(
            selected(["all".into()].into_iter()).unwrap().len(),
            ARMS.len()
        );
        assert!(selected(["typo".into()].into_iter()).is_err());
        assert_eq!(
            selected(["read_ids".into(), "read_ids".into()].into_iter()).unwrap(),
            ["read_ids"]
        );
    }
}
