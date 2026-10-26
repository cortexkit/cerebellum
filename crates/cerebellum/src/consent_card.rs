//! Consent rendering keeps display choices and the answer schema in agreement.
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::time::Duration;

/// How long a login consent card (`browser.capture_login`,
/// `browser.import_login`) stays open on the person's phone.
///
/// Thirty minutes, the span a browser origin grant card stays open
/// (`management::PHONE_CONSENT_DEADLINE`), because a person takes minutes to
/// notice a phone prompt and a shorter card shows them an "expired, retry"
/// note instead of the question. The call that files the card waits for only
/// part of this (`computer_grants::CONSENT_PARK_LIMIT`); an answer that
/// arrives after the call returned is remembered for the agent's retry.
pub(crate) const LOGIN_CARD_LIFETIME: Duration = Duration::from_secs(30 * 60);

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Effect {
    Grant,
    Decline,
}

#[derive(Serialize)]
pub(crate) struct ConsentOption {
    id: String,
    label: String,
    effect: Effect,
    /// A sentence shown under the label explaining what choosing it allows.
    /// The code asking for consent records the grant's ceiling and duration by
    /// option id; display text does not decide what is authorized.
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    /// What the agent should do after a late answer instead of retrying the
    /// original call. Omitted when retrying that call is the right next step.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_step: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<&'static str>,
}

#[derive(Serialize)]
pub(crate) struct DeclineOption {
    id: String,
    label: String,
    effect: Effect,
}

impl ConsentOption {
    pub fn grant(id: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            effect: Effect::Grant,
            detail: None,
            next_step: None,
            group: None,
        }
    }
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
    pub fn danger(mut self) -> Self {
        self.group = Some("danger");
        self
    }
    pub fn with_next_step(mut self, next_step: impl Into<String>) -> Self {
        self.next_step = Some(next_step.into());
        self
    }
    pub fn decline(id: impl Into<String>, label: impl Into<String>) -> DeclineOption {
        DeclineOption {
            id: id.into(),
            label: label.into(),
            effect: Effect::Decline,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TargetKind {
    Site,
    App,
    Machine,
}

#[derive(Serialize)]
pub(crate) struct Target {
    pub kind: TargetKind,
    pub label: String,
}

#[derive(Serialize)]
pub(crate) struct Fact {
    pub label: String,
    pub value: String,
}
impl Fact {
    pub fn new(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
        }
    }
}

/// How loudly the person's phone announces a card.
///
/// Prefrontal core, which puts consent questions to the person, refuses a
/// consent request without one. The rule this crate
/// follows: `High` when a tool call is held open while the person decides, so
/// the agent is stuck until they answer; `Normal` when the question was asked
/// ahead and the call that raised it has already returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Urgency {
    Normal,
    High,
}

/// What a grant made from a card is bound to, sent as the card's `scope`.
///
/// Always a JSON object whose values are the ones the grant is actually keyed
/// on (an origin, a bundle identity, a profile uuid), never prose and never a
/// filesystem path: it is what the person's answer is recorded against.
/// Prefrontal core refuses a consent request that carries neither a scope nor
/// an argument digest, so every card carries one.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(transparent)]
pub(crate) struct Scope(Map<String, Value>);

impl Scope {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.0.insert(key.to_string(), value.into());
        self
    }
}

/// Whether an approval after the in-call wait can still take effect.
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LateExecution {
    /// Runs held work or records approval for a matching retry.
    Execute,
    /// Records and reports the answer without authorizing any work.
    #[allow(
        dead_code,
        reason = "Every current card can still apply a late approval."
    )]
    NotifyOnly,
}

pub(crate) struct ConsentCard {
    pub title: String,
    pub prompt: String,
    pub target: Target,
    pub facts: Vec<Fact>,
    pub grants: Vec<ConsentOption>,
    pub decline: DeclineOption,
    pub expires_in: Duration,
    pub material_damage: bool,
    pub late_execution: LateExecution,
    pub urgency: Urgency,
    pub scope: Scope,
    pub duration: Option<Value>,
}

impl ConsentCard {
    /// The separate decline is always the last option, and it is also the
    /// card's `default` and `on_expiry` answer, so a card nobody answers
    /// grants nothing.
    ///
    /// The card is returned as `{"params": ...}`; `cingulate_client::card`
    /// turns those params into the `consent.request` sent to Cingulate.
    pub fn render(self) -> Value {
        let default = &self.decline.id;
        let ids: Vec<_> = self
            .grants
            .iter()
            .map(|o| &o.id)
            .chain(std::iter::once(&self.decline.id))
            .collect();
        let options: Vec<_> = self
            .grants
            .iter()
            .map(|o| json!(o))
            .chain(std::iter::once(json!(self.decline)))
            .collect();
        let mut params = json!({
            "kind": "consent", "title": self.title, "prompt": self.prompt,
            "target": self.target, "facts": self.facts, "options": options,
            "default": default, "on_expiry": "deny", "urgency": self.urgency,
            "scope": self.scope,
            "expires_in_ms": self.expires_in.as_millis() as u64,
            "material_damage": self.material_damage, "late_execution": self.late_execution,
            "requestedSchema": {"type": "object", "properties": {
                "decision": {"type": "string", "enum": ids}
            }, "required": ["decision"], "additionalProperties": false}
        });
        if let Some(duration) = self.duration {
            params["duration"] = duration;
        }
        json!({ "params": params })
    }
}

#[cfg(test)]
pub(crate) fn assert_contract(body: &Value, ids: &[&str], decline: &str) {
    let p = &body["params"];
    assert_eq!(p["kind"], "consent");
    assert!(!ids.is_empty());
    assert_eq!(
        p["options"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ids
    );
    assert_eq!(p["default"], decline);
    assert_eq!(p["on_expiry"], "deny");
    assert_eq!(
        p["requestedSchema"]["properties"]["decision"]["enum"],
        json!(ids)
    );
    for option in p["options"].as_array().unwrap() {
        assert_eq!(
            option["effect"],
            if option["id"] == decline {
                "decline"
            } else {
                "grant"
            }
        );
    }
}

/// Why Prefrontal core refuses a consent request: the `code` and `message` of
/// core's `Refusal`.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CoreRefusal {
    pub code: &'static str,
    pub message: String,
}

#[cfg(test)]
impl std::fmt::Display for CoreRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

#[cfg(test)]
fn core_invalid(message: impl Into<String>) -> CoreRefusal {
    CoreRefusal {
        code: "elicitation_invalid_request",
        message: message.into(),
    }
}

/// The top-level keys `ConsentRequest` requires and the ones it also accepts.
/// Every struct core decodes is `deny_unknown_fields`, so any other key is
/// refused.
#[cfg(test)]
const CORE_REQUIRED_KEYS: [&str; 11] = [
    "kind",
    "title",
    "prompt",
    "options",
    "default",
    "urgency",
    "on_expiry",
    "material_damage",
    "late_execution",
    "target",
    "expires_in_ms",
];
#[cfg(test)]
const CORE_OPTIONAL_KEYS: [&str; 14] = [
    "requester_ref",
    "binding",
    "at_console",
    "call_key",
    "dedup_key",
    "scope",
    "duration",
    "args_digest",
    "session_ref",
    "parent_session_ref",
    "facts",
    "preview",
    "requestedSchema",
    "single_use",
];

/// The longest a consent request may stay open in Prefrontal core: a day.
#[cfg(test)]
const CORE_RETENTION_MS: i64 = 24 * 60 * 60 * 1000;

/// serde's decode of one `deny_unknown_fields` struct whose fields are named
/// in `required` and `optional`.
#[cfg(test)]
fn core_decode_struct(
    value: &Value,
    what: &str,
    required: &[&str],
    optional: &[&str],
) -> Result<(), CoreRefusal> {
    let Some(object) = value.as_object() else {
        return Err(core_invalid(format!(
            "invalid type: {what} is not an object"
        )));
    };
    if let Some(key) = object
        .keys()
        .find(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err(core_invalid(format!("unknown field `{key}` in {what}")));
    }
    if let Some(key) = required.iter().find(|key| !object.contains_key(**key)) {
        return Err(core_invalid(format!("missing field `{key}` in {what}")));
    }
    Ok(())
}

/// serde's decode of the named fields of `value` as `String`, or as
/// `Option<String>` (absent or null allowed) when `optional`.
#[cfg(test)]
fn core_decode_strings(value: &Value, keys: &[&str], optional: bool) -> Result<(), CoreRefusal> {
    for key in keys {
        let field = &value[*key];
        if !(field.is_string() || optional && field.is_null()) {
            return Err(core_invalid(format!(
                "invalid type: `{key}` is not a string"
            )));
        }
    }
    Ok(())
}

/// Local test checks for closed consent shapes and fail-closed option defaults.
///
/// Unknown option groups, danger defaults and danger-only grants are rejected:
/// removing broad choices must leave a usable, non-dangerous consent card.
/// These rules are checked against the copied `danger-option-group-v1` vectors
/// from Cingulate commit 6bb5f4d. Historical Prefrontal request vectors also
/// remain checked so the legacy renderer's field shapes do not regress.
///
/// This is not Cingulate's production validator. It checks both the renderer's
/// legacy fields (`requestedSchema`, `call_key`, `next_step`) and the mapped
/// wire's fields (`requester_ref`, `binding`, `at_console`).
#[cfg(test)]
pub(crate) fn core_verdict(params: &Value) -> Result<(), CoreRefusal> {
    // Decoding: shape, unknown and missing fields, and types.
    core_decode_struct(
        params,
        "the request",
        &CORE_REQUIRED_KEYS,
        &CORE_OPTIONAL_KEYS,
    )?;
    core_decode_strings(
        params,
        &[
            "kind",
            "title",
            "prompt",
            "default",
            "urgency",
            "on_expiry",
            "late_execution",
        ],
        false,
    )?;
    core_decode_strings(
        params,
        &[
            "call_key",
            "dedup_key",
            "args_digest",
            "session_ref",
            "parent_session_ref",
        ],
        true,
    )?;
    if !params["material_damage"].is_boolean() {
        return Err(core_invalid(
            "invalid type: `material_damage` is not a bool",
        ));
    }
    if params
        .get("single_use")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(core_invalid("single_use must be a boolean"));
    }
    let Some(expires_in_ms) = params["expires_in_ms"].as_i64() else {
        return Err(core_invalid("invalid type: `expires_in_ms` is not an i64"));
    };
    let Some(options) = params["options"].as_array() else {
        return Err(core_invalid("invalid type: `options` is not a sequence"));
    };
    for option in options {
        core_decode_struct(
            option,
            "an option",
            &["id", "label", "effect"],
            &["detail", "next_step", "group"],
        )?;
        core_decode_strings(option, &["id", "label", "effect"], false)?;
        core_decode_strings(option, &["detail", "next_step"], true)?;
        if option
            .get("group")
            .is_some_and(|group| !group.is_null() && group != "danger")
        {
            return Err(core_invalid("unknown option group"));
        }
    }
    let target = &params["target"];
    core_decode_struct(target, "target", &["kind", "label"], &[])?;
    core_decode_strings(target, &["kind", "label"], false)?;
    // `facts` defaults to empty when absent, but a present null is not a list.
    if let Some(facts) = params.get("facts") {
        let Some(facts) = facts.as_array() else {
            return Err(core_invalid("invalid type: `facts` is not a sequence"));
        };
        for fact in facts {
            core_decode_struct(fact, "a fact", &["label", "value"], &[])?;
            core_decode_strings(fact, &["label", "value"], false)?;
        }
    }
    let preview = &params["preview"];
    if !preview.is_null() {
        core_decode_struct(preview, "preview", &["label", "text"], &[])?;
        core_decode_strings(preview, &["label", "text"], false)?;
    }

    // Validation, in `ConsentRequest::validate`'s order. Every field read
    // below was checked for its type above.
    let text = |key: &str| params[key].as_str().unwrap_or_default();
    let blank = |value: &Value| value.as_str().unwrap_or_default().trim().is_empty();
    if params.get("single_use").is_some() && text("kind") != "consent" {
        return Err(core_invalid("single_use requires consent kind"));
    }
    if text("kind") != "consent" {
        return Err(CoreRefusal {
            code: "elicitation_unknown_kind",
            message: "only consent is supported".into(),
        });
    }
    if text("title").trim().is_empty() || text("prompt").trim().is_empty() || options.is_empty() {
        return Err(core_invalid(
            "title, prompt and nonempty options are required",
        ));
    }
    let mut option_ids: Vec<&str> = Vec::new();
    for option in options {
        let id = option["id"].as_str().unwrap_or_default();
        if id.trim().is_empty() || blank(&option["label"]) || option_ids.contains(&id) {
            return Err(core_invalid(
                "option ids must be unique and nonempty; labels must be nonempty",
            ));
        }
        option_ids.push(id);
    }
    // An absent or null schema is not checked. A present one must carry a
    // decision enum of strings equal to the option ids as a set: core sorts
    // both before comparing.
    let schema = &params["requestedSchema"];
    if !schema.is_null() {
        let mismatch = || core_invalid("requestedSchema decision enum must equal option ids");
        let mut schema_ids = schema
            .pointer("/properties/decision/enum")
            .and_then(Value::as_array)
            .and_then(|values| values.iter().map(Value::as_str).collect::<Option<Vec<_>>>())
            .ok_or_else(mismatch)?;
        let mut offered = option_ids.clone();
        schema_ids.sort_unstable();
        offered.sort_unstable();
        if schema_ids != offered {
            return Err(mismatch());
        }
    }
    let Some(default) = options.iter().find(|o| o["id"] == params["default"]) else {
        return Err(core_invalid("default must name an option"));
    };
    if default["effect"] != "decline" || text("on_expiry") != "deny" {
        return Err(CoreRefusal {
            code: "elicitation_fail_closed_required",
            message: "consent requires a decline default and on_expiry deny".into(),
        });
    }
    if default["group"] == "danger" {
        return Err(CoreRefusal {
            code: "elicitation_fail_closed_required",
            message: "the default must not be in the danger group".into(),
        });
    }
    let grants: Vec<_> = options
        .iter()
        .filter(|option| option["effect"] == "grant")
        .collect();
    if !grants.is_empty() && grants.iter().all(|option| option["group"] == "danger") {
        return Err(core_invalid(
            "at least one grant must be outside the danger group",
        ));
    }
    if !matches!(text("urgency"), "low" | "normal" | "high")
        || !matches!(text("late_execution"), "execute" | "notify_only")
    {
        return Err(core_invalid("invalid urgency or late_execution"));
    }
    if expires_in_ms <= 0 || expires_in_ms > CORE_RETENTION_MS {
        return Err(core_invalid(
            "expires_in_ms must be positive and at most 24 hours",
        ));
    }
    // Core decodes `scope` as `Option<Value>`, so an explicit null is absent.
    if blank(&params["args_digest"]) && params["scope"].is_null() {
        return Err(core_invalid("provide args_digest or scope"));
    }
    if blank(&target["kind"]) || blank(&target["label"]) {
        return Err(core_invalid("target kind and label must be nonempty"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn card(grants: Vec<ConsentOption>) -> ConsentCard {
        ConsentCard {
            title: "Consent".into(),
            prompt: "Allow access?".into(),
            target: Target {
                kind: TargetKind::Machine,
                label: "machine".into(),
            },
            facts: vec![],
            grants,
            decline: ConsentOption::decline("deny", "Don't allow"),
            expires_in: Duration::from_secs(300),
            material_damage: true,
            late_execution: LateExecution::NotifyOnly,
            urgency: Urgency::Normal,
            scope: Scope::new().with("takeover", "machine"),
            duration: None,
        }
    }
    #[test]
    fn decline_is_last_and_is_the_default() {
        let body = card(vec![
            ConsentOption::grant("first", "First"),
            ConsentOption::grant("second", "Second"),
        ])
        .render();
        assert_contract(&body, &["first", "second", "deny"], "deny");
        assert_eq!(body["params"]["options"][2]["effect"], "decline");
        assert_eq!(
            body["params"]["options"][2]["id"],
            body["params"]["default"]
        );
    }
    #[test]
    fn default_is_the_decline_not_a_grant() {
        let body = card(vec![ConsentOption::grant("allow", "Allow")]).render();
        assert_contract(&body, &["allow", "deny"], "deny");
    }

    #[test]
    fn late_execution_renders_the_builders_explicit_choice() {
        let mut execute = card(vec![ConsentOption::grant("allow", "Allow")]);
        execute.late_execution = LateExecution::Execute;
        assert_eq!(execute.render()["params"]["late_execution"], "execute");
        let notify = card(vec![ConsentOption::grant("allow", "Allow")]);
        assert_eq!(notify.render()["params"]["late_execution"], "notify_only");
    }

    #[test]
    fn call_key_and_next_step_are_optional_strings_in_the_closed_card_schema() {
        let body = card(vec![ConsentOption::grant("allow", "Allow").with_next_step(
            "Call browser_use with action present for https://example.test.",
        )])
        .render();
        let mut params = body["params"].clone();
        params["call_key"] = json!("pf:schema");
        assert_eq!(core_verdict(&params), Ok(()));
        params["call_key"] = json!(7);
        assert!(core_verdict(&params)
            .unwrap_err()
            .message
            .contains("call_key"));
        params["call_key"] = json!("pf:schema");
        params["options"][0]["next_step"] = json!(false);
        assert!(core_verdict(&params)
            .unwrap_err()
            .message
            .contains("next_step"));
        params["options"][0]["next_step"] = Value::Null;
        assert_eq!(core_verdict(&params), Ok(()));
        params["options"][0]["unknown"] = json!("still refused");
        assert!(core_verdict(&params)
            .unwrap_err()
            .message
            .contains("unknown field"));
    }

    #[test]
    fn single_use_is_an_optional_boolean_only_for_consent_requests() {
        let body = card(vec![ConsentOption::grant("allow", "Allow")]).render();
        let mut params = body["params"].clone();
        assert_eq!(core_verdict(&params), Ok(()));
        params["single_use"] = json!(true);
        assert_eq!(core_verdict(&params), Ok(()));
        params["single_use"] = json!(false);
        assert_eq!(core_verdict(&params), Ok(()));
        params["single_use"] = json!("yes");
        let invalid_type = core_verdict(&params).unwrap_err();
        assert_eq!(invalid_type.code, "elicitation_invalid_request");
        assert!(invalid_type.message.contains("single_use"));
        params["single_use"] = json!(true);
        params["kind"] = json!("browser");
        let invalid_kind = core_verdict(&params).unwrap_err();
        assert_eq!(invalid_kind.code, "elicitation_invalid_request");
        assert!(invalid_kind.message.contains("single_use"));
    }

    /// Prefrontal's consent request vectors, copied byte for byte from
    /// prefrontal's `test-vectors/elicitation-request-v1/` (see the README
    /// beside the directory for the source commit).
    const REQUEST_VECTORS: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/elicitation-request-v1"
    );

    /// The SHA-256 of the copied `SHA256SUMS`. The manifest covers every other
    /// file but cannot cover itself, so the vectors' README asks consumers to
    /// pin its hash.
    const REQUEST_VECTORS_MANIFEST_SHA256: &str =
        "70617099cddb426b8ce4b6cf49d04337e58dd61230f909bc0bcba31c73c64c88";

    pub(super) fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// Every file under `dir`, as a path relative to `root` with `/` between
    /// components, the form `SHA256SUMS` names them in.
    fn files_under(root: &std::path::Path, dir: &std::path::Path, found: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                files_under(root, &path, found);
            } else {
                let relative = path.strip_prefix(root).unwrap();
                found.push(
                    relative
                        .components()
                        .map(|c| c.as_os_str().to_string_lossy().into_owned())
                        .collect::<Vec<_>>()
                        .join("/"),
                );
            }
        }
    }

    /// The vectors are trusted only as the exact bytes Prefrontal published:
    /// an edited or reformatted body could agree with this crate's mirror and
    /// disagree with core.
    #[test]
    fn the_request_vectors_are_the_ones_prefrontal_published() {
        let root = std::path::Path::new(REQUEST_VECTORS);
        let manifest = std::fs::read(root.join("SHA256SUMS")).unwrap();
        assert_eq!(
            sha256_hex(&manifest),
            REQUEST_VECTORS_MANIFEST_SHA256,
            "SHA256SUMS is not the manifest Prefrontal published"
        );
        let mut listed = Vec::new();
        for line in String::from_utf8(manifest).unwrap().lines() {
            let (expected, name) = line
                .split_once("  ")
                .unwrap_or_else(|| panic!("SHA256SUMS line is not `<hash>  <path>`: {line}"));
            let bytes = std::fs::read(root.join(name))
                .unwrap_or_else(|error| panic!("{name} is listed but unreadable: {error}"));
            assert_eq!(
                sha256_hex(&bytes),
                expected,
                "{name} does not match SHA256SUMS"
            );
            listed.push(name.to_string());
        }
        let mut present = Vec::new();
        files_under(root, root, &mut present);
        present.retain(|name| name != "SHA256SUMS");
        present.sort();
        listed.sort();
        assert_eq!(
            present, listed,
            "the vector directory holds files SHA256SUMS does not list, or lacks listed ones"
        );
    }

    /// Prefrontal's published verdicts on 31 request bodies, against
    /// `core_verdict`. Every valid card is accepted; every refused body is
    /// refused with core's code, in a message containing the part of core's
    /// diagnostic the vector pins. So the mirror the rendered cards are held to
    /// cannot accept anything core refuses among these bodies, nor refuse
    /// what core accepts.
    #[test]
    fn the_contract_mirror_agrees_with_core_on_every_request_vector() {
        let read = |path: std::path::PathBuf| -> Value {
            serde_json::from_slice(&std::fs::read(&path).unwrap())
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
        };
        let root = std::path::Path::new(REQUEST_VECTORS);
        let bodies = |dir: &str| {
            let mut names: Vec<String> = std::fs::read_dir(root.join(dir))
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|name| name.ends_with(".json") && !name.ends_with(".expected.json"))
                .collect();
            names.sort();
            names
        };

        let valid = bodies("valid");
        for name in &valid {
            let body = read(root.join("valid").join(name));
            if let Err(refusal) = core_verdict(&body) {
                panic!("valid/{name}: core accepts it, the mirror refused it: {refusal}");
            }
        }

        let refused = bodies("refused");
        for name in &refused {
            let body = read(root.join("refused").join(name));
            let expected = read(
                root.join("refused")
                    .join(name.replace(".json", ".expected.json")),
            );
            let refusal = core_verdict(&body).err().unwrap_or_else(|| {
                panic!("refused/{name}: core refuses it, the mirror accepted it")
            });
            assert_eq!(
                refusal.code, expected["code"],
                "refused/{name}: wrong refusal code ({refusal})"
            );
            let pinned = expected["message_contains"].as_str().unwrap();
            assert!(
                refusal.message.contains(pinned),
                "refused/{name}: `{}` does not contain core's `{pinned}`",
                refusal.message
            );
        }
        assert_eq!(
            (valid.len(), refused.len()),
            (7, 24),
            "the vector set changed size; check it was updated deliberately"
        );
    }
}

/// Every kind of consent card this crate sends. Each test builds its kind's
/// card with the builder production calls, turns it into the Cingulate
/// `consent.request` production sends (with the deadline the call site
/// enforces as `expires_in_ms`), and checks:
///
/// - for the same inputs as the kind's pinned file in
///   `tests/fixtures/cingulate-consent-cards-v1`, that the request is
///   byte-identical to that file;
/// - for every case, the card's urgency and its `scope` (the values the
///   resulting grant is keyed on).
///
/// One test per kind, so the test that goes red names the kind that changed.
#[cfg(test)]
mod every_card_kind {
    use super::*;
    use crate::authorization::{HazardClass, Severity};
    use crate::cingulate_client::card::{consent_request, CardKind, CardRequest};
    use crate::computer_grants::{AppIdentity, GrantNeed, NoIdentityReader};
    use std::sync::Arc;

    /// The key of the agent's tool call that raised a card. The pinned files
    /// carry this one as their `requester_ref`.
    const GOLDEN_CALL_KEY: &str = "pf:card-golden";

    /// The `consent.request` production sends to Cingulate for `body`, as
    /// raised by a tool call whose key is [`GOLDEN_CALL_KEY`]. Also checks
    /// that a call without a key sends the same request minus
    /// `requester_ref`.
    fn as_sent(kind: CardKind, body: Value, deadline: Duration) -> CardRequest {
        let unkeyed = consent_request(kind, &body, deadline, None, None, None)
            .unwrap_or_else(|error| panic!("{kind:?}: {error:?}"));
        assert!(
            unkeyed.params.get("requester_ref").is_none(),
            "{kind:?}: a keyless card gained a key"
        );
        let keyed = consent_request(kind, &body, deadline, Some(GOLDEN_CALL_KEY), None, None)
            .unwrap_or_else(|error| panic!("{kind:?}: {error:?}"));
        assert_eq!(keyed.params["requester_ref"], GOLDEN_CALL_KEY);
        let mut stripped = keyed.params.clone();
        stripped.as_object_mut().unwrap().remove("requester_ref");
        assert_eq!(
            stripped, unkeyed.params,
            "{kind:?}: the call key changed the rest of the card"
        );
        // `next_steps` holds, by option id, what the agent is told to do after
        // that option is chosen (such as "call present"). Cingulate refuses it
        // on the card, so cerebellum puts it in its own reply to the agent,
        // where it must read as one short sentence.
        for step in keyed.next_steps.values() {
            assert!(!step.trim().is_empty() && step.chars().count() <= 200);
            assert!(
                !step.contains(['\n', '\r']),
                "next_step must be one sentence"
            );
        }
        keyed
    }

    /// The pinned Cingulate card for one kind, as the bytes on disk.
    fn golden(name: &str) -> String {
        let path = std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/cingulate-consent-cards-v1"
        ))
        .join(name);
        std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{name}: {error}"))
    }

    /// `params` are byte-identical to the pinned card `name`.
    fn assert_golden(name: &str, params: &Value) {
        assert_eq!(
            format!("{}\n", serde_json::to_string_pretty(params).unwrap()),
            golden(name),
            "{name}: the card changed from its pinned bytes"
        );
    }

    /// What every card promises Cingulate: a `consent` card whose scope is a
    /// nonempty object (never a digest stand-in or prose), and none of
    /// `requestedSchema`, `call_key` or an option's `next_step`, which
    /// Cingulate's closed request format refuses.
    fn assert_cingulate_accepts(kind: &str, params: &Value) {
        assert_eq!(params["kind"], "consent", "{kind}: kind");
        assert!(
            params["scope"].as_object().is_some_and(|s| !s.is_empty()),
            "{kind}: scope is not a nonempty object: {}",
            params["scope"]
        );
        for field in ["requestedSchema", "call_key"] {
            assert!(params.get(field).is_none(), "{kind}: carries {field}");
        }
        for option in params["options"].as_array().unwrap() {
            assert!(
                option.get("next_step").is_none(),
                "{kind}: an option carries next_step"
            );
        }
    }

    fn assert_card(kind: &str, params: &Value, urgency: &str, scope: Value) {
        assert_cingulate_accepts(kind, params);
        assert_eq!(
            params["late_execution"], "execute",
            "{kind}: late_execution"
        );
        assert_eq!(params["urgency"], urgency, "{kind}: urgency");
        assert_eq!(params["scope"], scope, "{kind}: scope");
    }

    fn assert_browser_site_access_card(kind: CardKind, urgency: Urgency, wire: &str, golden: &str) {
        use crate::management::BrowserGrantChoice;
        let origins = vec!["https://example.com".to_string()];
        let hazards = vec![HazardClass::CredentialFormSubmit.as_str().to_string()];
        for choices in [
            &[BrowserGrantChoice::SiteThirtyMinutes][..],
            &[
                BrowserGrantChoice::SiteThirtyMinutes,
                BrowserGrantChoice::OriginAlways,
            ][..],
        ] {
            let body = crate::management::browser_grant_question(
                &origins,
                &hazards,
                Severity::new(4, true, false),
                urgency,
                choices,
            );
            let params = as_sent(kind, body, crate::management::PHONE_CONSENT_DEADLINE).params;
            assert_card(
                golden,
                &params,
                wire,
                json!({"origins": origins, "tier": 4, "hazards": hazards}),
            );
            if choices.len() == 2 {
                assert_golden(golden, &params);
            }
        }
    }

    #[test]
    fn browser_site_access_in_call_card_decodes_in_core() {
        assert_browser_site_access_card(
            CardKind::WebsiteAccessInCall,
            Urgency::High,
            "high",
            "website-access-in-call.json",
        );
    }

    #[test]
    fn browser_site_access_in_advance_card_decodes_in_core() {
        assert_browser_site_access_card(
            CardKind::WebsiteAccessInAdvance,
            Urgency::Normal,
            "normal",
            "website-access-in-advance.json",
        );
    }

    #[test]
    fn public_browser_site_access_cards_decode_in_core() {
        let origins = vec!["https://example.com".to_string()];
        for (kind, urgency, wire) in [
            (CardKind::WebsiteAccessInCall, Urgency::High, "high"),
            (CardKind::WebsiteAccessInAdvance, Urgency::Normal, "normal"),
        ] {
            let severity = Severity::new(2, false, false);
            let choices = crate::management::offered_browser_grant_choices(
                &origins,
                &Default::default(),
                severity,
                true,
            );
            let body = crate::management::browser_grant_question(
                &origins,
                &[],
                severity,
                urgency,
                &choices,
            );
            let params = as_sent(kind, body, crate::management::PHONE_CONSENT_DEADLINE).params;
            assert_card(
                "public sites",
                &params,
                wire,
                json!({"origins": origins, "tier": 2}),
            );
            assert!(params["options"]
                .as_array()
                .unwrap()
                .iter()
                .any(|o| o["id"] == "allow_all_sites_30m"));
        }
    }

    /// The site-access card for each option set it can offer, pinned as the
    /// exact `params` the production builder renders, so the phone app can
    /// check its decoder against the same bytes.
    ///
    /// Each card is built by the production builder from the option set the
    /// production offering rule picks for its case, compared with the pinned
    /// file, and mapped to the Cingulate request it is raised as, which must
    /// keep every option the card offers. `SHA256SUMS` beside the files pins
    /// each file's hash. Run with `CEREBELLUM_WRITE_SITE_CARD_VECTORS=1` to
    /// rewrite the files and the sums after a deliberate change to the card.
    #[tokio::test]
    async fn browser_site_access_card_vectors_are_pinned() {
        use crate::management::{offered_browser_grant_choices, BrowserGrantChoice};
        use std::collections::BTreeSet;
        const DIR: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/browser-site-access-card-v1"
        );
        let public = vec!["https://example.com".to_string()];
        let private = vec!["http://10.0.0.5".to_string()];
        let credential = BTreeSet::from([HazardClass::CredentialFormSubmit]);
        let none = BTreeSet::new();
        let all = |choices: &[BrowserGrantChoice]| {
            choices
                .iter()
                .map(|choice| choice.option_id())
                .chain(["deny"])
                .collect::<Vec<_>>()
        };
        /// The vector's file, the card's origins and hazards, the ceiling
        /// the request needs, whether the session may be offered standing
        /// answers, and the option ids the card must carry.
        type Case<'a> = (
            &'a str,
            &'a Vec<String>,
            &'a BTreeSet<HazardClass>,
            Severity,
            bool,
            &'a [&'a str],
        );
        let cases: [Case<'_>; 5] = [
            (
                "all-options.json",
                &public,
                &none,
                Severity::new(2, false, false),
                true,
                &[
                    "allow_30m",
                    "allow_origin_always",
                    "allow_all_sites_30m",
                    "allow_all_sites_always",
                    "deny",
                ],
            ),
            (
                "no-all-sites-level-4.json",
                &public,
                &none,
                Severity::new(4, false, false),
                true,
                &["allow_30m", "allow_origin_always", "deny"],
            ),
            (
                "no-all-sites-hazard.json",
                &public,
                &credential,
                Severity::new(4, true, false),
                true,
                &["allow_30m", "allow_origin_always", "deny"],
            ),
            (
                "no-all-sites-private-origin.json",
                &private,
                &none,
                Severity::new(2, false, false),
                true,
                &["allow_30m", "allow_origin_always", "deny"],
            ),
            (
                "worker-options.json",
                &public,
                &none,
                Severity::new(2, false, false),
                false,
                &["allow_30m", "allow_all_sites_30m", "deny"],
            ),
        ];
        let write = std::env::var_os("CEREBELLUM_WRITE_SITE_CARD_VECTORS").is_some();
        let mut sums = String::new();
        for (name, origins, hazards, severity, standing, expected_ids) in cases {
            let choices = if standing {
                offered_browser_grant_choices(origins, hazards, severity, true)
            } else {
                crate::permission_cards::browser_choices(
                    origins,
                    hazards,
                    severity,
                    Some(&crate::agent_grants::GrantHolder::Worker {
                        agent_id: "head".into(),
                        scope_ref: "worker".into(),
                    }),
                    true,
                )
            };
            assert_eq!(all(&choices), expected_ids, "{name}: offered options");
            let hazards_wire: Vec<String> = hazards
                .iter()
                .map(|hazard| hazard.as_str().to_string())
                .collect();
            let body = crate::management::browser_grant_question(
                origins,
                &hazards_wire,
                severity,
                Urgency::High,
                &choices,
            );
            let params = body["params"].clone();
            let sent = as_sent(
                CardKind::WebsiteAccessInCall,
                body,
                crate::management::PHONE_CONSENT_DEADLINE,
            )
            .params;
            assert_cingulate_accepts(name, &sent);
            assert_eq!(sent["late_execution"], "execute", "{name}: late_execution");
            assert_eq!(
                sent["options"], params["options"],
                "{name}: Cingulate is offered other options than the card"
            );
            // The closed option shape permits the optional `group: "danger"` field.
            for option in params["options"].as_array().unwrap() {
                let keys: BTreeSet<&str> = option
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect();
                assert!(
                    keys.is_subset(&BTreeSet::from([
                        "id", "label", "effect", "detail", "group"
                    ])),
                    "{name}: option carries {keys:?}"
                );
            }
            let rendered = format!("{}\n", serde_json::to_string_pretty(&params).unwrap());
            let path = std::path::Path::new(DIR).join(name);
            if write {
                std::fs::create_dir_all(DIR).unwrap();
                std::fs::write(&path, &rendered).unwrap();
            }
            let pinned = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("{name}: {error}\nrendered:\n{rendered}"));
            assert_eq!(
                pinned, rendered,
                "{name}: the card changed from the pinned vector"
            );
            let digest = super::tests::sha256_hex(pinned.as_bytes());
            eprintln!("{name} sha256 {digest}");
            sums.push_str(&format!("{digest}  {name}\n"));
        }
        let sums_path = std::path::Path::new(DIR).join("SHA256SUMS");
        if write {
            std::fs::write(&sums_path, &sums).unwrap();
        }
        assert_eq!(
            std::fs::read_to_string(&sums_path).unwrap(),
            sums,
            "SHA256SUMS does not match the pinned vectors"
        );
    }

    #[tokio::test]
    async fn login_import_card_decodes_in_core() {
        let presence = |transfer| crate::login_import::BrowserPresence {
            browser: "chrome".into(),
            name: "Google Chrome".into(),
            persistent_rows: 1,
            session_rows: 0,
            transfer,
            reason: None,
        };
        for (case, presence, golden) in [
            (
                "a copyable login",
                vec![presence("available")],
                Some("login-import.json"),
            ),
            ("nothing copyable", vec![presence("unsupported")], None),
        ] {
            let body = crate::login_import::import_question("https://x.com", "x.com", &presence);
            let request = as_sent(CardKind::LoginImport, body, super::LOGIN_CARD_LIFETIME);
            let params = &request.params;
            assert_card(case, params, "high", json!({"origin": "https://x.com"}));
            assert_login_card_life(case, &request);
            if let Some(golden) = golden {
                assert_golden(golden, params);
            }
            // The "sign in yourself" option tells the agent to call present
            // next. That instruction goes in cerebellum's reply to the agent,
            // never on the card.
            assert_eq!(
                request.next_steps,
                std::collections::BTreeMap::from([(
                    "hand_off".to_string(),
                    "Call browser_use with action present for https://x.com.".to_string()
                )]),
                "{case}: next steps"
            );
        }
    }

    #[tokio::test]
    async fn login_import_hand_off_for_a_long_origin_keeps_a_bounded_next_step() {
        let origin = format!(
            "https://{}.{}.{}.test",
            "a".repeat(60),
            "b".repeat(60),
            "c".repeat(60)
        );
        let body = crate::login_import::import_question(&origin, &origin[8..], &[]);
        let request = as_sent(CardKind::LoginImport, body, super::LOGIN_CARD_LIFETIME);
        let params = &request.params;
        let step = request.next_steps["hand_off"].as_str();
        assert_eq!(
            step,
            "Call browser_use with action present for the origin in this consent card's scope."
        );
        assert!(step.chars().count() <= 200);
        assert_eq!(params["scope"]["origin"], origin);
    }

    #[tokio::test]
    async fn login_capture_card_decodes_in_core() {
        let request = crate::login_capture::CaptureRequest {
            credential_domain: "ollama.com".into(),
            account: "work".into(),
            fetch_url: "https://ollama.com/settings".into(),
            login_url: "https://ollama.com/signin".into(),
        };
        let body = crate::login_capture::consent_question(&request);
        let card = as_sent(CardKind::LoginCapture, body, super::LOGIN_CARD_LIFETIME);
        let params = &card.params;
        assert_card(
            "capture_login",
            params,
            "high",
            json!({"credential_domain": "ollama.com", "account": "work"}),
        );
        assert_login_card_life("capture_login", &card);
        assert_golden("login-capture.json", params);
    }

    /// Late login approval authorizes a matching retry, with or without the
    /// negotiated single-use wire flag. It never launches login work by itself.
    fn assert_login_card_life(kind: &str, card: &CardRequest) {
        for single_use in [false, true] {
            let negotiated =
                card.clone()
                    .for_features(crate::cingulate_client::features::CingulateFeatures {
                        option_group: true,
                        single_use,
                        no_expiry: false,
                    });
            let params = &negotiated.params;
            assert_eq!(params["expires_in_ms"], 1_800_000, "{kind}: expires_in_ms");
            assert_eq!(
                params["single_use"].as_bool(),
                single_use.then_some(true),
                "{kind}: single_use"
            );
            assert_eq!(
                params["late_execution"], "execute",
                "{kind}: late_execution, single_use={single_use}"
            );
        }
    }

    #[tokio::test]
    async fn app_control_cards_decode_in_core() {
        let need = GrantNeed::App {
            bundle_identity: "com.example.Editor".into(),
            display_name: "Editor".into(),
            code: Arc::new(NoIdentityReader),
        };
        let team = AppIdentity {
            team_id: Some("ABCDE12345".into()),
            designated_requirement: "certificate leaf[subject.OU] = \"ABCDE12345\"".into(),
            ad_hoc: false,
            apple_anchored: false,
        };
        let apple = AppIdentity {
            team_id: None,
            designated_requirement: "anchor apple".into(),
            ad_hoc: false,
            apple_anchored: true,
        };
        let with_always: &[&'static str] = &[
            "allow_30m",
            "allow_always",
            "computer_30m",
            "computer_always",
            "deny",
        ];
        let temporary_only: &[&'static str] = &["allow_30m", "computer_30m", "deny"];
        for (case, offered, signature_changed, identity, scope) in [
            (
                "always offered",
                with_always,
                false,
                &team,
                json!({"app": "com.example.Editor", "team_id": "ABCDE12345"}),
            ),
            (
                "always not offered",
                temporary_only,
                false,
                &team,
                json!({"app": "com.example.Editor", "team_id": "ABCDE12345"}),
            ),
            (
                "signature changed",
                temporary_only,
                true,
                &team,
                json!({"app": "com.example.Editor", "team_id": "ABCDE12345"}),
            ),
            (
                "signed by Apple",
                with_always,
                false,
                &apple,
                json!({"app": "com.example.Editor", "apple_anchored": true}),
            ),
        ] {
            let body = crate::computer_grants::question_body(
                &need,
                offered,
                signature_changed,
                Some(identity),
            );
            let params = as_sent(
                CardKind::AppControl,
                body,
                crate::computer_grants::APP_QUESTION_DEADLINE,
            )
            .params;
            assert_card(case, &params, "high", scope);
            assert_eq!(params["target"]["label"], "Editor", "{case}");
            if case == "always offered" {
                assert_golden("app-control.json", &params);
            }
        }
    }

    #[tokio::test]
    async fn takeover_card_decodes_in_core() {
        let body = crate::computer_grants::question_body(
            &GrantNeed::Takeover,
            &["allow_once", "computer_30m", "computer_always", "deny"],
            false,
            None,
        );
        let params = as_sent(
            CardKind::Takeover,
            body,
            crate::computer_grants::TAKEOVER_QUESTION_DEADLINE,
        )
        .params;
        assert_card("takeover", &params, "high", json!({"takeover": "machine"}));
        assert_golden("takeover.json", &params);
    }

    #[tokio::test]
    async fn profile_root_rebind_card_decodes_in_core() {
        use crate::profile::{BirthTime, ManagedRootIdentity, RebindReport, RootIdentityFacts};
        let root_path = "/Users/someone/Library/Application Support/cerebellum/profiles";
        let birth_time = BirthTime {
            unix_seconds: 1_700_000_000,
            nanoseconds: 5,
        };
        let new_identity = RootIdentityFacts {
            formula: 2,
            path: root_path.into(),
            inode: 42,
            birth_time,
        };
        for (case, old_identity, old_scope) in [
            (
                "hash-only identity",
                ManagedRootIdentity::HashOnly("a1b2c3".into()),
                json!({"digest": "a1b2c3"}),
            ),
            (
                "fact identity",
                ManagedRootIdentity::Facts(RootIdentityFacts {
                    inode: 41,
                    ..new_identity.clone()
                }),
                json!({"formula": 2, "inode": 41, "birth_time": birth_time}),
            ),
        ] {
            let preview = RebindReport {
                old_identity,
                new_identity: new_identity.clone(),
                generation_before: 7,
                generation_after: 8,
                record_count: 3,
            };
            let body = crate::management::profile_root_rebind_question(root_path, &preview);
            let params = as_sent(
                CardKind::ProfileReidentification,
                body,
                crate::management::PHONE_CONSENT_DEADLINE,
            )
            .params;
            assert_card(
                case,
                &params,
                "normal",
                json!({
                    "old_identity": old_scope,
                    "new_identity": {"formula": 2, "inode": 42, "birth_time": birth_time},
                    "generation": 7,
                }),
            );
            assert!(
                !params["scope"].to_string().contains("/Users"),
                "{case}: the scope names a filesystem path"
            );
            if case == "hash-only identity" {
                assert_golden("profile-reidentification.json", &params);
            }
        }
    }

    #[tokio::test]
    async fn stuck_profile_clear_card_decodes_in_core() {
        use crate::launch_recovery::{
            ClearPreview, ProcessReading, ProfileEvidence, SingletonLockReading,
        };
        let preview = ClearPreview {
            agent_project_id: "project-1".into(),
            profile_uuid: "7f0c2a8e-0000-4000-8000-000000000001".into(),
            sequence: 12,
            reason: crate::browser_launch::RecoveryPendingReason::AttestationUntrusted,
            launched_at: None,
            evidence: ProfileEvidence {
                processes: ProcessReading::NoneNamesDirectory { examined: 3 },
                singleton_lock: SingletonLockReading::Absent,
            },
        };
        let body = crate::management::launch_recovery_clear_question(&preview);
        let params = as_sent(
            CardKind::StuckProfileClearance,
            body,
            crate::management::PHONE_CONSENT_DEADLINE,
        )
        .params;
        assert_golden("stuck-profile-clearance.json", &params);
        assert_card(
            "stuck-profile clear",
            &params,
            "normal",
            json!({"profile_uuid": "7f0c2a8e-0000-4000-8000-000000000001", "sequence": 12}),
        );
    }

    #[tokio::test]
    async fn user_browser_site_card_decodes_in_core() {
        let body = crate::user_browser::site_question(
            "https://example.net",
            3,
            &std::collections::BTreeSet::from([HazardClass::CredentialFormSubmit]),
            true,
        );
        let params = as_sent(
            CardKind::UserBrowserSite,
            body,
            crate::user_browser::CONSENT_DEADLINE,
        )
        .params;
        assert_cingulate_accepts("user-browser site", &params);
        assert_eq!(params["late_execution"], "execute");
        assert_golden("user-browser-site.json", &params);
    }
}
