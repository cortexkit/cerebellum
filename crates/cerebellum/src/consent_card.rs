//! Consent rendering keeps display choices and the answer schema in agreement.
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::time::Duration;

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
        }
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

pub(crate) struct ConsentCard {
    pub title: String,
    pub prompt: String,
    pub target: Target,
    pub facts: Vec<Fact>,
    pub grants: Vec<ConsentOption>,
    pub decline: DeclineOption,
    pub expires_in: Duration,
    pub material_damage: bool,
    pub urgency: Urgency,
    pub scope: Scope,
    pub duration: Option<Value>,
}

impl ConsentCard {
    /// The separate decline is always last, and silence selects it rather than a grant.
    pub fn render(self, ask_id: &str) -> Value {
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
            "material_damage": self.material_damage, "late_execution": "notify_only",
            "requestedSchema": {"type": "object", "properties": {
                "decision": {"type": "string", "enum": ids}
            }, "required": ["decision"], "additionalProperties": false}
        });
        if let Some(duration) = self.duration {
            params["duration"] = duration;
        }
        json!({"jsonrpc": "2.0", "method": "elicitation/create", "id": ask_id, "params": params})
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
const CORE_OPTIONAL_KEYS: [&str; 9] = [
    "dedup_key",
    "scope",
    "duration",
    "args_digest",
    "session_ref",
    "parent_session_ref",
    "facts",
    "preview",
    "requestedSchema",
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

/// Prefrontal core's verdict on these consent `params`: `Ok` when core would
/// accept them, otherwise the first refusal core would give.
///
/// Core decodes the `params` of every `elicitation/create` whose `kind` is
/// `consent` and answers `not_put_to_anyone` when it cannot. The person never
/// sees that card, and the agent only learns that nobody was asked. This
/// mirrors `ConsentRequest::decode` (serde with `deny_unknown_fields` on every
/// struct) and `ConsentRequest::validate`, in their order, from prefrontal's
/// `crates/prefrontal-core-store/src/elicitation.rs` at commit
/// d15391996594ce24ba53aa42fd1c31bb85922745. Refusal codes are core's, and
/// each message contains core's wording; serde's own wording is only
/// approximated (`unknown field `x``, `missing field `x``).
///
/// It is the only place that contract is written down in this crate. It is
/// held to Prefrontal's published request vectors (see
/// `the_contract_mirror_agrees_with_core_on_every_request_vector`), so it
/// cannot accept a body core refuses among those vectors, and every rendered
/// card is held to it.
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
    let Some(expires_in_ms) = params["expires_in_ms"].as_i64() else {
        return Err(core_invalid("invalid type: `expires_in_ms` is not an i64"));
    };
    let Some(options) = params["options"].as_array() else {
        return Err(core_invalid("invalid type: `options` is not a sequence"));
    };
    for option in options {
        core_decode_struct(option, "an option", &["id", "label", "effect"], &["detail"])?;
        core_decode_strings(option, &["id", "label", "effect"], false)?;
        core_decode_strings(option, &["detail"], true)?;
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
        .render("order");
        assert_contract(&body, &["first", "second", "deny"], "deny");
        assert_eq!(body["params"]["options"][2]["effect"], "decline");
        assert_eq!(
            body["params"]["options"][2]["id"],
            body["params"]["default"]
        );
    }
    #[test]
    fn default_is_the_decline_not_a_grant() {
        let body = card(vec![ConsentOption::grant("allow", "Allow")]).render("default");
        assert_contract(&body, &["allow", "deny"], "deny");
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

    fn sha256_hex(bytes: &[u8]) -> String {
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

/// Every kind of consent card this crate sends, built by the same function
/// production calls, put through `Elicitor::ask` with the deadline its call
/// site uses (which is what stamps `expires_in_ms` on the wire), and held to
/// Prefrontal core's decode contract in [`core_verdict`].
///
/// One test per kind, so a card core would refuse is named by the test that
/// goes red. Each test also pins the urgency the kind was assigned and the
/// scope it binds, built from the values its grant is keyed on.
#[cfg(test)]
mod every_card_kind {
    use super::*;
    use crate::authorization::{HazardClass, Severity};
    use crate::computer_grants::{AppIdentity, GrantNeed, NoIdentityReader};
    use crate::elicit::Elicitor;
    use std::sync::Arc;

    /// The `params` exactly as they leave this module, with the
    /// `expires_in_ms` that `Elicitor::ask` writes from `deadline` in place of
    /// the builder's.
    async fn as_sent(body: Value, deadline: Duration) -> Value {
        let elicitor = Arc::new(Elicitor::new());
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let asking = {
            let elicitor = Arc::clone(&elicitor);
            tokio::spawn(async move { elicitor.ask(&tx, 1, 1, body, deadline).await })
        };
        let frame = rx.recv().await.expect("the card is sent");
        asking.abort();
        let sent: Value = serde_json::from_slice(&frame.body).unwrap();
        sent["params"].clone()
    }

    /// Core's contract, plus what this crate promises on top of it: a scope
    /// that is a nonempty object (never a digest stand-in or prose) and the
    /// MCP answer schema beside the options.
    fn assert_core_accepts(kind: &str, params: &Value) {
        if let Err(refusal) = core_verdict(params) {
            panic!("{kind}: Prefrontal core would refuse this card: {refusal}\n{params:#}");
        }
        assert!(
            params["scope"].as_object().is_some_and(|s| !s.is_empty()),
            "{kind}: scope is not a nonempty object: {}",
            params["scope"]
        );
        assert!(
            params["requestedSchema"].is_object(),
            "{kind}: no requestedSchema"
        );
    }

    fn assert_card(kind: &str, params: &Value, urgency: &str, scope: Value) {
        assert_core_accepts(kind, params);
        assert_eq!(params["urgency"], urgency, "{kind}: urgency");
        assert_eq!(params["scope"], scope, "{kind}: scope");
    }

    #[tokio::test]
    async fn browser_site_access_cards_decode_in_core() {
        let origins = vec!["https://login.example".to_string()];
        let hazards = vec![HazardClass::CredentialFormSubmit.as_str().to_string()];
        for (path, urgency, wire) in [
            ("asked ahead by open_grant", Urgency::Normal, "normal"),
            ("held open in the browser call", Urgency::High, "high"),
        ] {
            let body = crate::management::browser_grant_question(
                "browser-grant",
                &origins,
                &hazards,
                Severity::new(4, true, false),
                urgency,
            );
            let params = as_sent(body, crate::management::PHONE_CONSENT_DEADLINE).await;
            assert_card(
                path,
                &params,
                wire,
                json!({"origins": origins, "tier": 4, "hazards": hazards}),
            );
        }
        let body = crate::management::browser_grant_question(
            "browser-grant",
            &origins,
            &[],
            Severity::new(2, false, false),
            Urgency::Normal,
        );
        let params = as_sent(body, crate::management::PHONE_CONSENT_DEADLINE).await;
        assert_card(
            "no hazards",
            &params,
            "normal",
            json!({"origins": origins, "tier": 2}),
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
        for (case, presence) in [
            ("a copyable login", vec![presence("available")]),
            ("nothing copyable", vec![presence("unsupported")]),
        ] {
            let body =
                crate::login_import::import_question("import", "https://x.com", "x.com", &presence);
            let params = as_sent(body, crate::login_import::ELICITATION_DEADLINE).await;
            assert_card(case, &params, "high", json!({"origin": "https://x.com"}));
        }
    }

    #[tokio::test]
    async fn login_capture_card_decodes_in_core() {
        let request = crate::login_capture::CaptureRequest {
            credential_domain: "ollama.com".into(),
            account: "work".into(),
            fetch_url: "https://ollama.com/settings".into(),
            login_url: "https://ollama.com/signin".into(),
        };
        let body = crate::login_capture::consent_question(&request, "capture-login-test");
        let params = as_sent(body, crate::login_import::ELICITATION_DEADLINE).await;
        assert_card(
            "capture_login",
            &params,
            "high",
            json!({"credential_domain": "ollama.com", "account": "work"}),
        );
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
        let with_always: &[&'static str] = &["allow_conversation", "allow_always", "deny"];
        let conversation_only: &[&'static str] = &["allow_conversation", "deny"];
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
                conversation_only,
                false,
                &team,
                json!({"app": "com.example.Editor", "team_id": "ABCDE12345"}),
            ),
            (
                "signature changed",
                conversation_only,
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
                "app",
                &need,
                offered,
                signature_changed,
                Some(identity),
            );
            let params = as_sent(body, crate::computer_grants::APP_QUESTION_DEADLINE).await;
            assert_card(case, &params, "high", scope);
            assert_eq!(params["target"]["label"], "Editor", "{case}");
        }
    }

    #[tokio::test]
    async fn takeover_card_decodes_in_core() {
        let body = crate::computer_grants::question_body(
            "takeover",
            &GrantNeed::Takeover,
            &["allow_conversation", "deny"],
            false,
            None,
        );
        let params = as_sent(body, crate::computer_grants::TAKEOVER_QUESTION_DEADLINE).await;
        assert_card("takeover", &params, "high", json!({"takeover": "machine"}));
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
            let body =
                crate::management::profile_root_rebind_question("rebind", root_path, &preview);
            let params = as_sent(body, crate::management::PHONE_CONSENT_DEADLINE).await;
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
        let body = crate::management::launch_recovery_clear_question("clear", &preview);
        let params = as_sent(body, crate::management::PHONE_CONSENT_DEADLINE).await;
        assert_card(
            "stuck-profile clear",
            &params,
            "normal",
            json!({"profile_uuid": "7f0c2a8e-0000-4000-8000-000000000001", "sequence": 12}),
        );
    }
}
