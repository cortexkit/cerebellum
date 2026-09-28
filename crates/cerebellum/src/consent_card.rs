//! Consent rendering keeps display choices and the answer schema in agreement.
use serde::Serialize;
use serde_json::{json, Value};
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

pub(crate) struct ConsentCard {
    pub title: String,
    pub prompt: String,
    pub target: Target,
    pub facts: Vec<Fact>,
    pub grants: Vec<ConsentOption>,
    pub decline: DeclineOption,
    pub expires_in: Duration,
    pub material_damage: bool,
    pub scope: Option<Value>,
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
            "default": default, "on_expiry": "deny",
            "expires_in_ms": self.expires_in.as_millis() as u64,
            "material_damage": self.material_damage, "late_execution": "notify_only",
            "requestedSchema": {"type": "object", "properties": {
                "decision": {"type": "string", "enum": ids}
            }, "required": ["decision"], "additionalProperties": false}
        });
        if let Some(scope) = self.scope {
            params["scope"] = scope;
        }
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
            scope: None,
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
}
