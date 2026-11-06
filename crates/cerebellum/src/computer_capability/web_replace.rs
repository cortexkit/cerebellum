//! Web editors receive real input, never AXValue or AXSelectedText writes.

use super::element_actions::{web_ancestry, ElementJournal};
use cerebellum_computer::app_state::source::{AppStateSource, ElementHandle};
use cerebellum_computer::platform::ProcessGrant;
use cerebellum_core::journal::{JournalStorage, Redactor, SeverityTaxonomy};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

/// The input dispatcher has more diagnostics than write_text's frozen wire
/// schema. Keep unsupported failure evidence in the response's `remedy` text
/// rather than adding fields or outcome words to that schema.
pub(super) fn write_reply(mut reply: Value) -> Value {
    use cerebellum_computer::platform::vocabulary::COMPUTER_ACTION_VOCABULARY_ARTIFACT;
    use std::sync::OnceLock;
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    let schema = SCHEMA.get_or_init(|| {
        let vocabulary: Value = serde_json::from_slice(COMPUTER_ACTION_VOCABULARY_ARTIFACT)
            .expect("embedded vocabulary is valid JSON");
        vocabulary["rows"]
            .as_array()
            .expect("vocabulary rows")
            .iter()
            .find(|row| row["capability_id"] == "computer.write_text")
            .expect("write_text row")["result_schema"]
            .clone()
    });
    let properties = schema["properties"].as_object().expect("result properties");
    let object = reply.as_object_mut().expect("input reply object");
    let mut details = serde_json::Map::new();
    object.retain(|key, value| {
        if properties.contains_key(key) {
            true
        } else {
            details.insert(key.clone(), value.clone());
            false
        }
    });
    for (field, fallback) in [
        ("outcome", "delivery_unconfirmed"),
        ("effect_status", "effect_indeterminate"),
    ] {
        if let Some(value) = object.get(field) {
            let allowed = properties[field]["enum"].as_array().expect("result enum");
            if !allowed.contains(value) {
                details.insert(field.into(), value.clone());
                object.insert(field.into(), json!(fallback));
            }
        }
    }
    if object
        .get("outcome")
        .is_none_or(|outcome| outcome != "completed")
        && !details.is_empty()
    {
        let previous = object
            .get("remedy")
            .and_then(Value::as_str)
            .unwrap_or("Read state before trying again; input may have partially arrived.");
        object.insert(
            "remedy".into(),
            json!(format!(
                "{previous} Input delivery details: {}",
                Value::Object(details)
            )),
        );
    }
    reply
}

#[derive(Clone)]
pub(super) struct WebReplacement {
    pub element_id: String,
    pub handle: ElementHandle,
    pub grant: ProcessGrant,
    pub text: String,
}

fn refused() -> Value {
    json!({
        "outcome": "web_content_needs_type",
        "reason": "web_content_needs_type",
        "effect_status": "not_dispatched",
        "remedy": "web replacement needs a focused, editable field whose whole selection can be verified. No replacement keys were posted; read_state before trying again",
    })
}

impl WebReplacement {
    /// Check the addressed field again at the posting boundary. Selection alone
    /// does not prove where keys will land: the target must also retain focus.
    pub(super) fn select<R: Redactor, T: SeverityTaxonomy, S: JournalStorage>(
        &self,
        source: &dyn AppStateSource,
        grant: &ProcessGrant,
        journal: &mut ElementJournal<'_, R, T, S>,
    ) -> Result<(), Value> {
        if grant != &self.grant || web_ancestry(source, grant, &self.handle) != Some(true) {
            return Err(refused());
        }
        let facts = source.element_facts(&self.handle).map_err(|_| refused())?;
        if facts.is_secure() || !facts.value_settable {
            return Err(refused());
        }
        let focused = || {
            super::keystrokes::read_target_focus(source, grant)
                .ok()
                .flatten()
                .is_some_and(|focus| focus.handle.same_element(self.handle.as_ref()))
        };
        if !focused() {
            return Err(refused());
        }
        let before = source
            .text_value(&self.handle)
            .ok()
            .flatten()
            .ok_or_else(refused)?;
        let range = (0, before.encode_utf16().count());
        let token = journal
            .intent(grant, &self.element_id, "AXSelectedTextRange", "text")
            .map_err(|refusal| refusal.reply())?;
        let confirmed = source.select_range(&self.handle, range).is_ok()
            && source.selected_range(&self.handle).ok().flatten() == Some(range)
            && source.text_value(&self.handle).ok().flatten().as_ref() == Some(&before)
            && focused();
        journal
            .outcome(
                token,
                if confirmed {
                    "completed"
                } else {
                    "delivery_unconfirmed"
                },
            )
            .map_err(|_| refused())?;
        if confirmed {
            Ok(())
        } else {
            Err(refused())
        }
    }

    /// Exact value equality also covers clearing a nonempty selection. Merely
    /// finding the requested substring would accept an accidental append.
    pub(super) fn arrived(&self, source: &dyn AppStateSource, bound: Duration) -> bool {
        let deadline = Instant::now() + bound;
        loop {
            if source.text_value(&self.handle).ok().flatten().as_ref() == Some(&self.text) {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50).min(deadline - now));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cerebellum_computer::platform::vocabulary::validate_capability_result;

    #[test]
    fn write_reply_keeps_partial_input_and_held_state_evidence_in_existing_fields() {
        let reply = write_reply(json!({
            "outcome": "synthetic_dispatch_failed",
            "effect_status": "effect_indeterminate",
            "posts_returned": 2,
            "held_state": "unknown",
            "remedy": "Do not retry.",
        }));
        validate_capability_result("computer.write_text", &reply).unwrap();
        assert_eq!(reply["outcome"], "delivery_unconfirmed");
        let remedy = reply["remedy"].as_str().unwrap();
        for evidence in [
            "Do not retry.",
            "posts_returned",
            "2",
            "held_state",
            "unknown",
            "synthetic_dispatch_failed",
        ] {
            assert!(remedy.contains(evidence), "{reply}");
        }
    }

    #[test]
    fn write_reply_retains_no_post_evidence_without_a_new_effect_status() {
        let reply = write_reply(json!({
            "outcome": "web_content_needs_type",
            "effect_status": "not_dispatched",
        }));
        validate_capability_result("computer.write_text", &reply).unwrap();
        assert_eq!(reply["outcome"], "web_content_needs_type");
        assert_eq!(reply["effect_status"], "effect_indeterminate");
        assert!(reply["remedy"].as_str().unwrap().contains("not_dispatched"));
    }
}
