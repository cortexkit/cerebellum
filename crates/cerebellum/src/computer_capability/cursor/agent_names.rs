//! Display names read from Entorhinal, never from action arguments.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Default)]
pub(super) struct Names {
    token: Option<String>,
    agents: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct Reply {
    result: FleetIdentity,
}

#[derive(Deserialize)]
struct FleetIdentity {
    token: String,
    #[serde(default)]
    unchanged: bool,
    agents: Option<Vec<Value>>,
}

impl Names {
    pub(super) fn request(&self) -> Vec<u8> {
        let params = self
            .token
            .as_ref()
            .map_or(json!({}), |token| json!({"token":token}));
        serde_json::to_vec(&json!({"method":"agent.fleet_identity","params":params}))
            .unwrap_or_default()
    }

    pub(super) fn known(&self, agent: &str) -> Option<String> {
        self.agents.get(agent).cloned()
    }

    /// A failed refresh leaves the last verified names intact. A successful
    /// full list replaces them, including removing names for absent agents.
    pub(super) fn apply(&mut self, bytes: &[u8]) -> bool {
        let Ok(reply) = serde_json::from_slice::<Reply>(bytes) else {
            return false;
        };
        let reply = reply.result;
        if reply.token.is_empty() || reply.token.len() > 256 {
            return false;
        }
        if reply.unchanged {
            return self.token.as_ref() == Some(&reply.token) && reply.agents.is_none();
        }
        let Some(rows) = reply.agents.filter(|rows| rows.len() <= 1024) else {
            return false;
        };
        self.agents = rows
            .into_iter()
            .filter_map(|row| {
                let agent = row.get("agentId")?.as_str()?.to_string();
                let name = row.get("displayName")?.as_str()?.trim();
                if agent.is_empty() || name.is_empty() {
                    return None;
                }
                Some((
                    agent,
                    cerebellum_computer::app_state::render::one_line(name),
                ))
            })
            .collect();
        self.token = Some(reply.token);
        true
    }
}

pub(super) fn heading(name: Option<&str>, app: &str) -> String {
    let text = name.map_or_else(|| app.to_string(), |name| format!("{name} is using {app}"));
    if text.chars().count() <= 128 {
        text
    } else {
        let mut text: String = text.chars().take(127).collect();
        text.push('…');
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    const VECTORS: &[u8] =
        include_bytes!("../../../tests/vectors/agent-identity-reads-v1/fleet-identity.json");

    #[test]
    fn published_fleet_identity_round_trips_its_token_and_unchanged_reply() {
        assert_eq!(
            format!("{:x}", Sha256::digest(VECTORS)),
            "b28ebd11a1a03b214c2f64b8f779c634a9a8d5016773e7a8e2d06b27871db6be"
        );
        let vectors: Vec<Value> = serde_json::from_slice(VECTORS).unwrap();
        let mut names = Names::default();
        assert_eq!(
            serde_json::from_slice::<Value>(&names.request()).unwrap(),
            json!({"method":"agent.fleet_identity","params":{}})
        );
        assert!(names.apply(&serde_json::to_vec(&vectors[0]["reply"]).unwrap()));
        assert_eq!(
            names.known("agent_0000000000000001").as_deref(),
            Some("Ada")
        );
        assert_eq!(
            names.known("agent_0000000000000002").as_deref(),
            Some("Lin")
        );
        assert!(names.known("agent_absent").is_none());
        assert_eq!(
            serde_json::from_slice::<Value>(&names.request()).unwrap()["params"],
            vectors[1]["request"]
        );
        assert!(names.apply(&serde_json::to_vec(&vectors[1]["reply"]).unwrap()));
        assert_eq!(
            names.known("agent_0000000000000001").as_deref(),
            Some("Ada")
        );
        assert!(!names.apply(&serde_json::to_vec(&vectors[2]["reply"]).unwrap()));
        assert_eq!(
            names.known("agent_0000000000000001").as_deref(),
            Some("Ada")
        );
        assert!(!Names::default().apply(&serde_json::to_vec(&vectors[1]["reply"]).unwrap()));
    }

    #[test]
    fn preview_headings_use_each_agents_registry_row_and_never_the_raw_id() {
        let mut names = Names::default();
        assert!(names.apply(br#"{"result":{"token":"one","agents":[{"agentId":"a","displayName":"CEREB"},{"agentId":"b","displayName":"ENTO"},{"agentId":"c","displayName":42}]}}"#));
        assert_eq!(
            heading(names.known("a").as_deref(), "TextEdit"),
            "CEREB is using TextEdit"
        );
        assert_eq!(
            heading(names.known("b").as_deref(), "Mail"),
            "ENTO is using Mail"
        );
        assert_eq!(heading(names.known("c").as_deref(), "TextEdit"), "TextEdit");
        assert_eq!(
            heading(names.known("agent_unknown").as_deref(), "TextEdit"),
            "TextEdit"
        );
    }
}
