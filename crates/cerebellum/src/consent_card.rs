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
/// Prefrontal core refuses a consent request without one. The rule this crate
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

/// Every top-level key Prefrontal core's `ConsentRequest` accepts. Core decodes
/// it with `deny_unknown_fields`, so a card with any other key is refused.
#[cfg(test)]
const CORE_REQUEST_KEYS: [&str; 20] = [
    "kind",
    "title",
    "prompt",
    "options",
    "default",
    "urgency",
    "dedup_key",
    "on_expiry",
    "material_damage",
    "scope",
    "duration",
    "args_digest",
    "late_execution",
    "session_ref",
    "parent_session_ref",
    "target",
    "facts",
    "preview",
    "expires_in_ms",
    "requestedSchema",
];

/// The longest a consent request may stay open in Prefrontal core: a day.
#[cfg(test)]
const CORE_RETENTION_MS: u64 = 24 * 60 * 60 * 1000;

/// The reasons Prefrontal core would refuse these consent `params`. Empty
/// when core would accept them.
///
/// Core decodes the `params` of every `elicitation/create` whose `kind` is
/// `consent` and answers `not_put_to_anyone` when it cannot. The person never
/// sees that card, and the agent only learns that nobody was asked. This
/// restates the `ConsentRequest` decode (every struct is
/// `deny_unknown_fields`) and `ConsentRequest::validate` from prefrontal's
/// `crates/prefrontal-core-store/src/elicitation.rs` at commit
/// f5957f2fe01f0bb3fe0e0c3619c6711d160b2504 ("consent: accept MCP
/// requestedSchema, ..."), so a card core would refuse fails in this crate's
/// tests instead of in front of a person.
///
/// It is the only place that contract is written down here. When Prefrontal
/// publishes request vectors for it, replace this body with a check against
/// them; callers only ask whether core would accept the params.
#[cfg(test)]
pub(crate) fn core_refusals(params: &Value) -> Vec<String> {
    let mut refusals = Vec::new();
    let Some(object) = params.as_object() else {
        return vec!["params is not an object".into()];
    };
    for key in object.keys() {
        if !CORE_REQUEST_KEYS.contains(&key.as_str()) {
            refusals.push(format!("unknown top-level key `{key}`"));
        }
    }
    for key in [
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
    ] {
        if !object.contains_key(key) {
            refusals.push(format!("missing required key `{key}`"));
        }
    }
    let nonempty = |value: &Value| value.as_str().is_some_and(|s| !s.trim().is_empty());
    let only_keys = |value: &Value, allowed: &[&str]| {
        value
            .as_object()
            .is_some_and(|o| o.keys().all(|k| allowed.contains(&k.as_str())))
    };

    if params["kind"] != "consent" {
        refusals.push("`kind` is not `consent`".into());
    }
    for key in ["title", "prompt"] {
        if !nonempty(&params[key]) {
            refusals.push(format!("`{key}` is not a nonempty string"));
        }
    }

    let options = params["options"].as_array().cloned().unwrap_or_default();
    if options.is_empty() {
        refusals.push("`options` is not a nonempty array".into());
    }
    let mut ids: Vec<&str> = Vec::new();
    for option in &options {
        if !only_keys(option, &["id", "label", "effect", "detail"]) {
            refusals.push(format!("option has a key core does not accept: {option}"));
        }
        if !nonempty(&option["id"]) || !nonempty(&option["label"]) || !option["effect"].is_string()
        {
            refusals.push(format!(
                "option needs a nonempty id and label and an effect: {option}"
            ));
        }
        let id = option["id"].as_str().unwrap_or_default();
        if ids.contains(&id) {
            refusals.push(format!("option id `{id}` is not unique"));
        }
        ids.push(id);
    }
    match options.iter().find(|o| o["id"] == params["default"]) {
        None => refusals.push("`default` names no option".into()),
        Some(option) if option["effect"] != "decline" => {
            refusals.push("`default` names an option that is not a decline".into())
        }
        Some(_) => {}
    }
    if params["on_expiry"] != "deny" {
        refusals.push("`on_expiry` is not `deny`".into());
    }
    if !matches!(params["urgency"].as_str(), Some("low" | "normal" | "high")) {
        refusals.push("`urgency` is not low, normal or high".into());
    }
    if !matches!(
        params["late_execution"].as_str(),
        Some("execute" | "notify_only")
    ) {
        refusals.push("`late_execution` is not execute or notify_only".into());
    }
    if !params["material_damage"].is_boolean() {
        refusals.push("`material_damage` is not a boolean".into());
    }
    if !params["expires_in_ms"]
        .as_u64()
        .is_some_and(|ms| (1..=CORE_RETENTION_MS).contains(&ms))
    {
        refusals.push("`expires_in_ms` is not positive and at most 24 hours".into());
    }
    // Core decodes both as optional, so an explicit null counts as absent.
    let has_digest = nonempty(&params["args_digest"]);
    let has_scope = !params["scope"].is_null();
    if !has_digest && !has_scope {
        refusals.push("neither `scope` nor `args_digest` is present".into());
    }
    for key in [
        "args_digest",
        "dedup_key",
        "session_ref",
        "parent_session_ref",
    ] {
        if !params[key].is_null() && !params[key].is_string() {
            refusals.push(format!("`{key}` is not a string"));
        }
    }
    let target = &params["target"];
    if !only_keys(target, &["kind", "label"])
        || !nonempty(&target["kind"])
        || !nonempty(&target["label"])
    {
        refusals.push(format!(
            "`target` is not exactly a nonempty kind and label: {target}"
        ));
    }
    if !params["facts"].is_null() {
        let facts_ok = params["facts"].as_array().is_some_and(|facts| {
            facts.iter().all(|fact| {
                only_keys(fact, &["label", "value"])
                    && fact["label"].is_string()
                    && fact["value"].is_string()
            })
        });
        if !facts_ok {
            refusals.push("`facts` is not a list of label and value strings".into());
        }
    }
    let preview = &params["preview"];
    if !preview.is_null()
        && !(only_keys(preview, &["label", "text"])
            && preview["label"].is_string()
            && preview["text"].is_string())
    {
        refusals.push("`preview` is not a label and text".into());
    }
    if !params["requestedSchema"].is_null() {
        // Core compares the two as sets, so order is not part of its contract.
        let mut answerable: Vec<&str> = params["requestedSchema"]
            .pointer("/properties/decision/enum")
            .and_then(Value::as_array)
            .map(|values| values.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let mut offered = ids.clone();
        answerable.sort_unstable();
        offered.sort_unstable();
        if answerable != offered {
            refusals.push("`requestedSchema` decision enum is not exactly the option ids".into());
        }
    }
    refusals
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

    /// `core_refusals` is the only thing standing between a malformed card and
    /// a silent `not_put_to_anyone`, so each rule it restates must actually
    /// refuse something. A check that accepted everything would pass every
    /// card test below without anyone noticing.
    #[test]
    fn core_refusals_refuses_each_thing_core_refuses() {
        let valid =
            card(vec![ConsentOption::grant("allow", "Allow")]).render("valid")["params"].clone();
        assert_eq!(core_refusals(&valid), Vec::<String>::new());
        let tamperings: [(&str, fn(&mut Value)); 16] = [
            ("unknown key", |p| p["surprise"] = json!(1)),
            ("no urgency", |p| {
                p.as_object_mut().unwrap().remove("urgency");
            }),
            ("urgency outside its set", |p| {
                p["urgency"] = json!("urgent")
            }),
            ("neither scope nor digest", |p| {
                p.as_object_mut().unwrap().remove("scope");
            }),
            ("null scope", |p| p["scope"] = Value::Null),
            ("empty digest only", |p| {
                p.as_object_mut().unwrap().remove("scope");
                p["args_digest"] = json!(" ");
            }),
            ("default is a grant", |p| p["default"] = json!("allow")),
            ("on_expiry not deny", |p| p["on_expiry"] = json!("allow")),
            ("late_execution outside its set", |p| {
                p["late_execution"] = json!("later")
            }),
            ("zero expiry", |p| p["expires_in_ms"] = json!(0)),
            ("expiry past a day", |p| {
                p["expires_in_ms"] = json!(CORE_RETENTION_MS + 1)
            }),
            ("duplicate option id", |p| {
                p["options"][0]["id"] = json!("deny")
            }),
            ("schema enum disagrees", |p| {
                p["requestedSchema"]["properties"]["decision"]["enum"] = json!(["allow"])
            }),
            ("extra target key", |p| p["target"]["path"] = json!("/")),
            ("no target label", |p| p["target"]["label"] = json!("")),
            ("extra option key", |p| p["options"][0]["why"] = json!("x")),
        ];
        for (name, tamper) in tamperings {
            let mut params = valid.clone();
            tamper(&mut params);
            assert!(!core_refusals(&params).is_empty(), "{name} was accepted");
        }
        let mut digest_only = valid.clone();
        digest_only.as_object_mut().unwrap().remove("scope");
        digest_only["args_digest"] = json!("sha256:abc");
        assert_eq!(core_refusals(&digest_only), Vec::<String>::new());
    }
}

/// Every kind of consent card this crate sends, built by the same function
/// production calls, put through `Elicitor::ask` with the deadline its call
/// site uses (which is what stamps `expires_in_ms` on the wire), and held to
/// Prefrontal core's decode contract in [`core_refusals`].
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

    /// The `params` exactly as they leave this module: the deadline
    /// `Elicitor::ask` writes over whatever the builder put there.
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
        let refusals = core_refusals(params);
        assert!(
            refusals.is_empty(),
            "{kind}: Prefrontal core would refuse this card: {refusals:?}\n{params:#}"
        );
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
        let body = crate::login_capture::consent_question(&request, Duration::from_secs(600));
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
