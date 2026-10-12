//! Cerebellum's consent cards, as Cingulate `consent.request` params.
//!
//! Every card cerebellum raises is built by the builders that also served the
//! reverse elicitation lane (see the module docs in `mod.rs`)
//! (`management::browser_grant_question`, `computer_grants::question_body`,
//! `login_import::import_question`, `login_capture::consent_question`,
//! `management::profile_root_rebind_question`,
//! `management::launch_recovery_clear_question`), which render an
//! `elicitation/create` body. This file lifts that body's `params` into
//! Cingulate's generic `consent` request and changes only what Cingulate's
//! closed request format requires, so the phone sees the same title, prompt,
//! target, facts, options, default, urgency, scope, lifetime and duration as
//! it did on the reverse elicitation lane. The differences:
//!
//! - `expires_in_ms` is stamped from the deadline the call site enforces, as
//!   that lane stamped it, so the number on the card is the number the
//!   code waits on.
//! - The originating call's key travels as `requester_ref` (opaque
//!   correlation, no dedup meaning), not `call_key`, which Cingulate refuses.
//! - `requestedSchema` is dropped: Cingulate checks it against the option
//!   ids and then discards it, so it adds nothing a closed option list does
//!   not already say.
//! - An option's `next_step` (what the agent should do after choosing it, such
//!   as "call present and sign in yourself") is taken off the card. It is an
//!   instruction to the agent, not a choice for the operator, and Cingulate
//!   refuses unknown option keys. It is kept here, by option id, for
//!   cerebellum's reply to the agent.

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::Value;

use super::wire;

/// The card families cerebellum raises, all as kind `consent`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CardKind {
    /// Browser site access asked while the browser call is held open.
    WebsiteAccessInCall,
    /// Browser site access asked ahead by `open_grant`.
    WebsiteAccessInAdvance,
    AppControl,
    Takeover,
    LoginImport,
    LoginCapture,
    /// The managed profile root changed identity and must be re-identified.
    ProfileReidentification,
    /// A browser profile stuck in launch recovery, to be cleared.
    StuckProfileClearance,
}

impl CardKind {
    pub const ALL: [Self; 8] = [
        Self::WebsiteAccessInCall,
        Self::WebsiteAccessInAdvance,
        Self::AppControl,
        Self::Takeover,
        Self::LoginImport,
        Self::LoginCapture,
        Self::ProfileReidentification,
        Self::StuckProfileClearance,
    ];

    /// Whether an approval of this card is consumed once rather than becoming
    /// a grant. An approval that arrives after the call that raised the card
    /// stopped waiting is recorded as single-use: the agent's next call of the
    /// same tool with the same arguments acts on it once and reports its
    /// execution back to Cingulate.
    pub fn single_use(self) -> bool {
        matches!(self, Self::LoginImport | Self::LoginCapture)
    }
}

/// A card ready to raise, and what cerebellum needs to read its answer.
#[derive(Debug, Clone, PartialEq)]
pub struct CardRequest {
    pub kind: CardKind,
    /// The `consent.request` params, exactly as sent.
    pub params: Value,
    /// Option ids whose effect is to grant.
    pub grant_ids: Vec<String>,
    /// The decline option's id, which is also the card's default.
    pub decline_id: String,
    /// What cerebellum tells the agent after each option, by option id. Never
    /// on the card.
    pub next_steps: BTreeMap<String, String>,
}

/// Why a rendered body could not become a request. Only a bug in a card
/// builder causes it. The card is then never raised, and the caller should
/// end the call as `Ending::DeliveryFailed`: a defect on this side, not a
/// person who could not be reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotACard(pub &'static str);

/// Turn a rendered card body into a Cingulate request.
///
/// `at_console` is the answering-machine constraint Cingulate defines: the
/// card can then be answered only at the daemon's own console. Production
/// passes `None` for every kind, takeover included. No answering surface at
/// the console exists yet, the phone cannot satisfy the constraint (so a
/// takeover card carrying it could never be approved), and nothing tells
/// cerebellum the daemon's machine id that the value must match.
pub fn consent_request(
    kind: CardKind,
    body: &Value,
    deadline: Duration,
    requester_ref: Option<&str>,
    dedup_key: Option<&str>,
    at_console: Option<&str>,
) -> Result<CardRequest, NotACard> {
    let mut params = body
        .get("params")
        .and_then(Value::as_object)
        .cloned()
        .ok_or(NotACard("the body has no params object"))?;
    if params.get("kind").and_then(Value::as_str) != Some(wire::KIND_CONSENT) {
        return Err(NotACard("the body is not a consent card"));
    }
    params.remove("requestedSchema");
    params.remove("call_key");
    params.insert(
        "expires_in_ms".into(),
        Value::from(u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX)),
    );
    let mut next_steps = BTreeMap::new();
    let mut grant_ids = Vec::new();
    let mut decline_id = None;
    let options = params
        .get_mut("options")
        .and_then(Value::as_array_mut)
        .ok_or(NotACard("the card has no options"))?;
    for option in options.iter_mut() {
        let option = option
            .as_object_mut()
            .ok_or(NotACard("an option is not an object"))?;
        let id = option
            .get("id")
            .and_then(Value::as_str)
            .ok_or(NotACard("an option has no id"))?
            .to_string();
        if let Some(Value::String(step)) = option.remove("next_step") {
            next_steps.insert(id.clone(), step);
        }
        match option.get("effect").and_then(Value::as_str) {
            Some("grant") => grant_ids.push(id),
            Some("decline") => decline_id = Some(id),
            _ => return Err(NotACard("an option is neither a grant nor the decline")),
        }
    }
    let decline_id = decline_id.ok_or(NotACard("the card has no decline option"))?;
    if let Some(reference) = requester_ref.filter(|reference| wire::is_requester_ref(reference)) {
        params.insert("requester_ref".into(), Value::from(reference));
    }
    if let Some(key) = dedup_key {
        params.insert("dedup_key".into(), Value::from(key));
    }
    if let Some(machine) = at_console {
        params.insert("at_console".into(), Value::from(machine));
    }
    Ok(CardRequest {
        kind,
        params: Value::Object(params),
        grant_ids,
        decline_id,
        next_steps,
    })
}

/// The fields of a card the operator's phone renders, in a form two cards
/// can be compared by. Cingulate's phone projection carries the request's
/// display fields unchanged, so equal projections are equal phone cards.
pub fn phone_visible(params: &Value) -> Value {
    const SHOWN: [&str; 15] = [
        "kind",
        "title",
        "prompt",
        "target",
        "facts",
        "options",
        "default",
        "urgency",
        "on_expiry",
        "scope",
        "expires_in_ms",
        "material_damage",
        "late_execution",
        "duration",
        "preview",
    ];
    let mut shown = serde_json::Map::new();
    for key in SHOWN {
        if let Some(value) = params.get(key) {
            shown.insert(key.to_string(), value.clone());
        }
    }
    if let Some(Value::Array(options)) = shown.get_mut("options") {
        for option in options {
            if let Some(option) = option.as_object_mut() {
                option
                    .retain(|key, _| matches!(key.as_str(), "id" | "label" | "effect" | "detail"));
            }
        }
    }
    Value::Object(shown)
}
