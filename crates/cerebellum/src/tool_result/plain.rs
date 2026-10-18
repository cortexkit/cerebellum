//! The words a model reads for one reply.
//!
//! A content/v1 reader shows the model only the reply's text and image parts;
//! the full reply travels beside them as structured content for programs.
//! Everything here therefore turns a reply object into plain sentences and
//! compact `name: value` lines, and never into JSON: a model handed a JSON
//! fragment spends attention parsing punctuation, and the operator's rule is
//! that none reaches it. Identifiers, codes, counts and flags that only a
//! program acts on stay in the structured copy; what a model needs to choose
//! its next call (an id to pass back, why a call was refused, what to do
//! next) is written out here.

use serde_json::{Map, Value};

/// Above this many bytes, the names of installed applications that are not
/// running are left out of the `list_apps` text and only counted. A full
/// Applications folder runs to several hundred names, which costs the model
/// thousands of tokens on every listing when it nearly always wants a running
/// application or one it can name.
const INSTALLED_NAMES_MAX_BYTES: usize = 3 * 1024;

/// A string, number or boolean as words, or a list of them joined with
/// commas. Objects and lists holding objects have no plain form here, so they
/// are left to the caller to describe member by member.
fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(true) => Some("yes".into()),
        Value::Bool(false) => Some("no".into()),
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::Array(_) | Value::Object(_) => None,
                other => scalar(other),
            })
            .collect::<Option<Vec<_>>>()
            .map(|items| items.join(", ")),
        Value::Null | Value::Object(_) => None,
    }
}

/// A code such as `state_changed_by_person` as the words it is made of.
fn words(code: &str) -> String {
    code.replace('_', " ")
}

/// Text as a sentence: first letter upper case and closing punctuation, so
/// remedies written as clauses read as sentences after the line before them.
pub(super) fn sentence(text: &str) -> String {
    let text = text.trim();
    let mut characters = text.chars();
    let Some(first) = characters.next() else {
        return String::new();
    };
    // A remedy may open with an action or field name (`list_apps shows…`),
    // which the model must type exactly, so such a word keeps its case.
    let first_word = text.split_whitespace().next().unwrap_or_default();
    let mut out: String = if first_word.contains(['_', '.']) {
        text.to_string()
    } else {
        first.to_uppercase().chain(characters).collect()
    };
    if !out.ends_with(['.', '!', '?', ':']) {
        out.push('.');
    }
    out
}

fn text<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    object.get(key).and_then(Value::as_str)
}

/// What happened, for outcomes that say more than "it worked". `None` for a
/// plain success, which needs no line at all.
fn outcome_line(code: &str, object: &Map<String, Value>) -> Option<String> {
    let target = text(object, "target");
    Some(match code {
        "ok" | "completed" | "ready" => return None,
        "consent_pending" => match text(object, "ask_id") {
            Some(ask) => format!("Waiting for the person to answer a consent question (ask_id {ask})."),
            None => "Waiting for the person to answer a consent question.".into(),
        },
        "no_running_app_named" => match target {
            Some(target) => format!("No running app is named {target}."),
            None => "No running app has that name.".into(),
        },
        "ambiguous_app" => {
            let names = object
                .get("candidates")
                .and_then(Value::as_array)
                .map(|candidates| {
                    candidates
                        .iter()
                        .map(|candidate| {
                            let name = text_of(candidate, "name").unwrap_or("unnamed");
                            match text_of(candidate, "bundle_identity") {
                                Some(bundle) => format!("{name} ({bundle})"),
                                None => name.to_string(),
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let subject = target.unwrap_or("The name");
            if names.is_empty() {
                format!("{subject} matches more than one app.")
            } else {
                format!("{subject} matches more than one app: {names}.")
            }
        }
        "invalid_request" => match (text(object, "field"), text(object, "reason")) {
            (Some(field), Some(reason)) => {
                format!("Invalid request: {field} is {}.", words(reason))
            }
            (Some(field), None) => format!("Invalid request: {field} is not accepted."),
            _ => "Invalid request.".into(),
        },
        "predicate_satisfied" => "The condition held.".into(),
        "timeout" => "Timed out: the condition was checked and never held.".into(),
        "indeterminate" => "Indeterminate: the target could not be read, which is not evidence that the condition is false.".into(),
        other => sentence(&words(other)),
    })
}

fn text_of<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn effect_line(status: &str, object: &Map<String, Value>) -> Option<String> {
    Some(match status {
        "effect_observed" => "The effect was observed.".into(),
        "no_effect_observed" => "No effect was observed.".into(),
        "not_dispatched" => "Nothing reached the app, so it is safe to retry.".into(),
        "effect_indeterminate" => match object.get("posts_returned").and_then(Value::as_u64) {
            Some(posts) => format!(
                "Whether it took effect is unknown; {posts} input posts returned before it stopped."
            ),
            None => "Whether it took effect is unknown.".into(),
        },
        _ => return None,
    })
}

/// The caption that goes with an image part, and the facts a later
/// coordinate call must echo: its id and its pixel size.
fn image_caption(object: &Map<String, Value>) -> Option<String> {
    let image = object.get("image")?.as_object()?;
    let dimension = |key: &str| {
        image
            .get(&format!("{key}_px"))
            .or_else(|| image.get(key))
            .or_else(|| object.get(&format!("image_{key}_px")))
            .and_then(Value::as_u64)
    };
    let mut caption = match text(image, "image_id") {
        Some(id) => format!("Image {id}"),
        None => "Image".to_string(),
    };
    if let (Some(width), Some(height)) = (dimension("width"), dimension("height")) {
        caption.push_str(&format!(", {width}×{height} px"));
    }
    caption.push('.');
    Some(caption)
}

/// What a refusal's `detail` adds that a model can act on. The rest of it
/// (internal step names, node ids, classifier facts) is diagnostics for
/// programs and stays structured.
fn detail_lines(detail: &Map<String, Value>, remedy: Option<&str>, lines: &mut Vec<String>) {
    if let Some(reason) = text(detail, "reason") {
        lines.push(format!("Reason: {}.", words(reason)));
    }
    match (text(detail, "field"), text(detail, "reason_code")) {
        (Some(field), Some(code)) => lines.push(format!("Field {field}: {}.", words(code))),
        (Some(field), None) => lines.push(format!("Field: {field}.")),
        (None, Some(code)) if text(detail, "reason").is_none() => {
            lines.push(format!("Reason: {}.", words(code)))
        }
        _ => {}
    }
    if let Some(permission) = text(detail, "permission") {
        lines.push(format!("Missing permission: {}.", words(permission)));
    }
    if let Some(label) = text(detail, "grant_label") {
        lines.push(format!("Grant asked for: {label}."));
    }
    if let Some(origin) = text(detail, "attempted_origin") {
        lines.push(format!("Site: {origin}."));
    }
    if let Some(hazard) = text(detail, "missing_hazard") {
        lines.push(format!("Undisclosed hazard: {hazard}."));
    }
    if let Some(request) = detail.get("grant_request").and_then(Value::as_object) {
        // The refusal's remedy names detail.grant_request, so the line keeps
        // that name and spells out the arguments open_grant takes.
        let members = ["origins", "hazards", "severity_tier"]
            .into_iter()
            .filter_map(|key| {
                let value = scalar(request.get(key)?)?;
                Some(format!(
                    "{key} {}",
                    if value.is_empty() {
                        "none".into()
                    } else {
                        value
                    }
                ))
            })
            .collect::<Vec<_>>();
        if !members.is_empty() {
            lines.push(format!("detail.grant_request: {}.", members.join("; ")));
        }
    }
    match (
        text(detail, "step"),
        detail.get("dispatched").and_then(Value::as_bool),
    ) {
        (Some(step), Some(false)) => lines.push(format!(
            "It stopped at the {} step; nothing was dispatched.",
            words(step)
        )),
        (Some(step), Some(true)) => lines.push(format!(
            "It stopped at the {} step, after input was dispatched.",
            words(step)
        )),
        _ => {}
    }
    if text(detail, "held_state") == Some("unknown") {
        lines.push("Whether input is still held down is unknown.".into());
    }
    // A remedy that points at `detail.<name>` needs that value in front of
    // the model, which cannot see the structured copy it names.
    let said = [
        "reason",
        "field",
        "reason_code",
        "permission",
        "grant_label",
        "attempted_origin",
        "missing_hazard",
        "grant_request",
        "step",
        "dispatched",
        "held_state",
    ];
    for (key, value) in detail {
        if said.contains(&key.as_str())
            || !remedy.is_some_and(|remedy| remedy.contains(&format!("detail.{key}")))
        {
            continue;
        }
        if let Some(value) = scalar(value) {
            lines.push(format!("detail.{key}: {value}"));
        }
    }
}

/// The `list_apps` view: running applications one per line with what a
/// target needs, then installed ones by name only.
fn list_apps_text(object: &Map<String, Value>, apps: &[Value]) -> String {
    // Names are application text: one line each, so no name can pose as
    // another entry.
    let field = |app: &Value, key: &str| {
        text_of(app, key).map(cerebellum_computer::app_state::render::one_line)
    };
    let mut running = Vec::new();
    let mut installed = Vec::new();
    for app in apps {
        let name = field(app, "name").unwrap_or_default();
        if app.get("running").and_then(Value::as_bool) == Some(true) {
            let mut line = name;
            if let Some(bundle) = field(app, "bundle_identity") {
                line.push_str(&format!(" · {bundle}"));
            }
            if let Some(pid) = app.get("pid").and_then(Value::as_i64) {
                line.push_str(&format!(" · pid {pid}"));
            }
            if app.get("frontmost").and_then(Value::as_bool) == Some(true) {
                line.push_str(" · frontmost");
            }
            running.push(line);
        } else {
            installed.push(name);
        }
    }
    let mut out = String::new();
    if running.is_empty() {
        out.push_str("No running app is listed.\n");
    } else {
        out.push_str("Running apps:\n");
        for line in &running {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !installed.is_empty() {
        let block = installed.join(", ");
        if block.len() <= INSTALLED_NAMES_MAX_BYTES {
            out.push_str(&format!(
                "Installed, not running ({}): {block}\n",
                installed.len()
            ));
        } else {
            out.push_str(&format!(
                "{} installed apps that are not running are not shown; call list_apps with text_filter to find one by name or bundle id.\n",
                installed.len()
            ));
        }
    }
    if object.get("truncated").and_then(Value::as_bool) == Some(true) {
        out.push_str("The list stops at 500 apps.\n");
    }
    out
}

/// The main body of a reply: the application or page state, or the app
/// list. `None` when the reply carries neither.
pub(super) fn body(object: &Map<String, Value>) -> Option<String> {
    if let Some(apps) = object.get("apps").and_then(Value::as_array) {
        return Some(list_apps_text(object, apps));
    }
    // If the reply has no top-level page text, use text from its optional read_page object.
    text(object, "state_text")
        .or_else(|| {
            object
                .get("read_page")
                .and_then(Value::as_object)
                .and_then(|read_page| text(read_page, "state_text"))
        })
        .map(str::to_owned)
}

/// Every fact line for a reply, in reading order: what happened, the
/// remedy, then the few facts the next call needs.
pub(super) fn facts(object: &Map<String, Value>, login_notice: Option<String>) -> Vec<String> {
    let mut lines = Vec::new();
    let outcome = text(object, "outcome");
    let failed = outcome.is_some_and(|code| !super::is_success(code));
    if let Some(notice) = login_notice {
        lines.push(notice);
    } else if let Some(line) = outcome.and_then(|code| outcome_line(code, object)) {
        lines.push(line);
    }
    if let Some(remedy) = text(object, "remedy").filter(|remedy| !remedy.trim().is_empty()) {
        // Some remedies are only the next call's name, `browser.launch`.
        if remedy.trim().contains(char::is_whitespace) {
            lines.push(sentence(remedy));
        } else {
            lines.push(format!("Next: {}.", remedy.trim()));
        }
    }
    if let Some(name) = text(object, "matched_app") {
        lines.push(format!("Using the running app {name}."));
    }
    if let Some(focused) = text(object, "focused_element_id") {
        lines.push(format!("Focused: {focused}."));
    }
    match object.get("unreadable_subtrees").and_then(Value::as_u64) {
        Some(1) => lines.push("1 part couldn't be read.".into()),
        Some(count) if count > 1 => lines.push(format!("{count} parts couldn't be read.")),
        _ => {}
    }
    if let Some(line) = text(object, "effect_status").and_then(|status| effect_line(status, object))
    {
        lines.push(line);
    }
    if text(object, "browser") == Some("user")
        && object.get("input_dispatched").and_then(Value::as_bool) == Some(true)
    {
        lines.push("Input was dispatched to the person's browser.".into());
    }
    if text(object, "browser") == Some("user") {
        // The tab handle and interaction epoch identify a tab the agent can use and whether its page has changed.
        if let Some(connected) = object.get("connected").and_then(Value::as_bool) {
            lines.push(if connected {
                "The Chrome extension is connected.".into()
            } else {
                "The Chrome extension is not connected.".into()
            });
            let tabs = object.get("tabs").and_then(Value::as_array);
            if let Some(tabs) = tabs.filter(|tabs| !tabs.is_empty()) {
                for tab in tabs {
                    let Some(handle) = text_of(tab, "tab") else {
                        continue;
                    };
                    let claimed = text_of(tab, "claim") == Some("claimed_by_this_route");
                    let claim = if claimed { "claimed" } else { "not claimed" };
                    match tab.get("interaction_epoch").and_then(Value::as_u64) {
                        Some(epoch) => lines.push(format!(
                            "Available tab {handle} is {claim} (interaction epoch {epoch})."
                        )),
                        None => lines.push(format!("Available tab {handle} is {claim}.")),
                    }
                }
            } else {
                lines.push("No tabs are available. Ask the person to move a tab into the Agent group or hand one over with the toolbar button.".into());
            }
        }
    }
    if text(object, "browser") == Some("user") && text(object, "outcome") == Some("ok") {
        if let Some(origin) = text(object, "origin") {
            lines.push(format!("Site access is authorized for {origin}."));
        }
    }
    if text(object, "browser") != Some("user") && text(object, "outcome") == Some("ready") {
        let session = text(object, "browser_session_id").unwrap_or("unknown");
        lines.push(format!("Own browser session {session} is ready."));
        if let Some(disposition) = text(object, "profile_disposition") {
            lines.push(format!("Profile disposition: {}.", words(disposition)));
        }
        if let Some(lease) = object.get("lease").and_then(Value::as_object) {
            if let Some(timeout) = lease.get("idle_timeout_ms").and_then(Value::as_u64) {
                lines.push(format!("Idle timeout: {timeout} ms."));
            }
            if let Some(expiry) = text(lease, "idle_expires_at") {
                lines.push(format!("Idle lease expires at {expiry}."));
            }
        }
    }
    if object.get("settled").and_then(Value::as_bool) == Some(false) {
        lines.push("Page settlement was not confirmed.".into());
        if let Some(reason) = text(object, "settlement_reason") {
            lines.push(sentence(reason));
        }
    }
    if object
        .get("popup_activated_briefly")
        .and_then(Value::as_bool)
        == Some(true)
    {
        lines.push("A popup was activated briefly.".into());
    }
    if object.get("refs_truncated").and_then(Value::as_bool) == Some(true) {
        lines.push("Some actionable references were left out; take another snapshot with filters or zoom before acting on missing controls.".into());
    }
    if let Some(frames) = object
        .get("omitted_frames")
        .and_then(Value::as_u64)
        .filter(|n| *n > 0)
    {
        lines.push(format!("Omitted {frames} embedded page frames."));
    }
    if let Some(steps) = object.get("steps").and_then(Value::as_array) {
        let steps = steps
            .iter()
            .map(|step| {
                let number = step.get("step").and_then(Value::as_u64).unwrap_or(0);
                let element = text_of(step, "element_id").unwrap_or("?");
                let outcome = text_of(step, "outcome").map(words).unwrap_or_default();
                format!("{number} {element} {outcome}")
            })
            .collect::<Vec<_>>();
        if !steps.is_empty() {
            lines.push(format!("Steps: {}.", steps.join("; ")));
        }
    }
    if let Some(step) = object.get("stopped_at").and_then(Value::as_u64) {
        lines.push(format!(
            "Stopped at step {step}; later presses were not attempted."
        ));
    }
    if text(object, "state_report") == Some("replacement") {
        lines.push("Most of the window changed, so this is its new outline.".into());
    }
    if object.get("zoom_found").and_then(Value::as_bool) == Some(false) {
        lines.push("The zoomed element is not there after the action.".into());
    }
    if let Some(truncation) = object.get("truncation") {
        let omitted = truncation
            .get("omitted_elements")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if text_of(truncation, "reason") == Some("label_truncated") && omitted == 0 {
            lines.push("Some long labels were shortened.".into());
        } else {
            lines.push(format!(
                "Shortened to fit the reply: {omitted} elements left out; zoom or filter to see them."
            ));
        }
    }
    if object.get("apps").is_none()
        && object.get("truncated").and_then(Value::as_bool) == Some(true)
    {
        lines.push("The text was cut short to fit the reply.".into());
    }
    if let Some(caption) = image_caption(object) {
        lines.push(caption);
    }
    if let Some(unavailable) = object.get("image_unavailable") {
        if let Some(reason) = text_of(unavailable, "reason") {
            lines.push(format!("No image: {}.", words(reason)));
        }
    }
    let read_page = object.get("read_page").and_then(Value::as_object);
    let snapshot_id = text(object, "snapshot_id")
        .or_else(|| read_page.and_then(|read_page| text(read_page, "snapshot_id")));
    if let Some(snapshot) = snapshot_id {
        // A snapshot's own header already names its id; say it once.
        let state = text(object, "state_text")
            .or_else(|| read_page.and_then(|read_page| text(read_page, "state_text")));
        if !state.is_some_and(|state| state.contains(snapshot)) {
            lines.push(format!("snapshot_id: {snapshot}"));
        }
    }
    for key in ["browser_session_id", "tab"] {
        if key == "browser_session_id"
            && text(object, "browser") != Some("user")
            && text(object, "outcome") == Some("ready")
        {
            continue;
        }
        if let Some(value) = object.get(key).and_then(scalar) {
            lines.push(format!("{key}: {value}"));
        }
    }
    if let Some(url) = text(object, "url_final") {
        lines.push(format!("Now at {url}."));
    }
    if outcome != Some("consent_pending") {
        if let Some(ask) = text(object, "ask_id") {
            lines.push(format!("ask_id: {ask}"));
        }
    }
    if let Some(ms) = object.get("expires_in_ms").and_then(Value::as_u64) {
        lines.push(format!("Expires in {} s.", ms.div_ceil(1000)));
    }
    if let Some(terminal) = text(object, "terminal_outcome") {
        lines.push(format!("The session ended: {}.", words(terminal)));
    }
    if let Some(revoked) = object
        .get("revoked")
        .and_then(Value::as_u64)
        .filter(|n| *n > 0)
    {
        lines.push(format!("Revoked: {revoked}."));
    }
    if let Some(pid) = object.get("pid").and_then(Value::as_i64) {
        lines.push(format!("pid {pid}."));
    }
    if object.get("has_window").and_then(Value::as_bool) == Some(false) {
        lines.push("It has no window yet.".into());
    }
    if outcome
        .is_some_and(|code| matches!(code, "launched" | "launched_no_window" | "already_running"))
        && object.get("frontmost").and_then(Value::as_bool) == Some(true)
    {
        lines.push("It made itself frontmost.".into());
    }
    if let Some(note) = text(object, "launch_note") {
        lines.push(sentence(note));
    }
    if let Some(evidence) = text(object, "evidence") {
        lines.push(format!("Evidence: {evidence}."));
    }
    if text(object, "installed_list") == Some("partial") {
        lines.push(
            "Not every installed app could be read in time, so the installed list is partial."
                .into(),
        );
    }
    if text(object, "screen_lock_state") == Some("unknown") {
        lines.push("Whether the screen was locked could not be read; an empty or missing element may mean it was.".into());
    }
    if object.get("grant_persisted").and_then(Value::as_bool) == Some(false) {
        lines.push(
            "The allow-always answer holds for this conversation only; it could not be saved."
                .into(),
        );
    }
    if failed {
        refusal_lines(object, outcome.unwrap_or_default(), &mut lines);
    }
    lines
}

/// What a refusal adds beyond its sentence and remedy: the request field or
/// application it is about, and the detail that tells the model how to fix it.
fn refusal_lines(object: &Map<String, Value>, code: &str, lines: &mut Vec<String>) {
    if code != "invalid_request" {
        if let Some(field) = text(object, "field") {
            lines.push(format!("Field: {field}."));
        }
        if let Some(reason) = text(object, "reason") {
            lines.push(format!("Reason: {}.", words(reason)));
        }
    }
    if !matches!(code, "no_running_app_named" | "ambiguous_app") {
        if let Some(target) = text(object, "target") {
            lines.push(format!("Target: {target}."));
        }
    }
    if let Some(bundle) = text(object, "bundle_identity") {
        lines.push(format!("App: {bundle}."));
    }
    if code != "ambiguous_app" {
        if let Some(candidates) = object.get("candidates").and_then(Value::as_array) {
            let names = candidates
                .iter()
                .filter_map(|candidate| text_of(candidate, "name"))
                .collect::<Vec<_>>();
            if !names.is_empty() {
                lines.push(format!("Candidates: {}.", names.join(", ")));
            }
        }
    }
    if let Some(instances) = object.get("instances").and_then(Value::as_array) {
        let instances = instances
            .iter()
            .filter_map(|instance| {
                let pid = instance.get("pid")?.as_i64()?;
                let windows = instance
                    .get("window_count")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                Some(format!("pid {pid} ({windows} windows)"))
            })
            .collect::<Vec<_>>();
        if !instances.is_empty() {
            lines.push(format!("Running instances: {}.", instances.join(", ")));
        }
    }
    if let Some(chord) = text(object, "chord") {
        lines.push(format!("Chord: {chord}."));
    }
    if let Some(scheme) = text(object, "scheme") {
        lines.push(format!("Scheme: {scheme}."));
    }
    if let Some(reason) = object
        .get("unreadable")
        .and_then(|unreadable| text_of(unreadable, "reason"))
    {
        lines.push(format!("Why: {}.", words(reason)));
    }
    if let Some(stage) = text(object, "stage") {
        lines.push(format!("Stage: {}.", words(stage)));
    }
    if let Some(detail) = object.get("detail").and_then(Value::as_object) {
        detail_lines(detail, text(object, "remedy"), lines);
    }
}
