//! The requester half of Cingulate's consent wire, as Cingulate's contract
//! `consent-requester-v2` (on top of `consent-requester-v1`) defines it.
//!
//! Requests are `{method, params}` envelopes; a success is `{result: ...}`;
//! a refusal is a transport Error frame whose body carries a string `code` and
//! `message`, never a result object. Nothing here decides what a card means:
//! this file only builds request bodies and reads the parts of a reply the
//! client branches on.

use serde_json::{json, Map, Value};

/// The module id of the consent module, the route target of every call.
pub const CINGULATE_MODULE_ID: &str = "cingulate";

pub const CONSENT_REQUEST: &str = "consent.request";
pub const CONSENT_AWAIT: &str = "consent.await";
pub const CONSENT_GET: &str = "consent.get";
pub const CONSENT_ANSWERS: &str = "consent.answers";
pub const CONSENT_ACK: &str = "consent.ack";
pub const CONSENT_WITHDRAW: &str = "consent.withdraw";
pub const CONSENT_REPORT_EXECUTION: &str = "consent.report_execution";
pub const CONSENT_DETACH: &str = "consent.detach";

/// The longest single `consent.await` Cingulate honours; a longer timeout is
/// capped to this, so asking for more only hides how long the wait really is.
pub const AWAIT_CAP_MS: u64 = 120_000;

/// The only kind cerebellum may raise. Cingulate refuses every other kind
/// from `reserved:cerebellum` with `elicitation_requester_refused`.
pub const KIND_CONSENT: &str = "consent";

/// One request body, serialized exactly as it goes on the wire.
pub fn envelope(method: &str, params: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"method": method, "params": params}))
        .expect("a JSON value always serializes")
}

pub fn await_params(elicitation_id: &str, timeout_ms: u64) -> Value {
    json!({"elicitation_id": elicitation_id, "timeout_ms": timeout_ms.min(AWAIT_CAP_MS)})
}

pub fn id_params(elicitation_id: &str) -> Value {
    json!({"elicitation_id": elicitation_id})
}

pub fn answers_params(since: i64) -> Value {
    json!({"since": since})
}

pub fn ack_params(cursor: i64) -> Value {
    json!({"cursor": cursor})
}

/// What the requester did with an answered card, reported once it is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Execution {
    Executed,
    ApprovedNotExecuted,
    OutcomeUnknown,
}

/// These predefined execution reasons avoid sending arbitrary diagnostics to the phone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionReason {
    SessionEnded,
    TargetGone,
    GrantStoreUnavailable,
    RefusedAtDispatch,
}

impl ExecutionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SessionEnded => "session_ended",
            Self::TargetGone => "target_gone",
            Self::GrantStoreUnavailable => "grant_store_unavailable",
            Self::RefusedAtDispatch => "refused_at_dispatch",
        }
    }
}

impl Execution {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Executed => "executed",
            Self::ApprovedNotExecuted => "approved_not_executed",
            Self::OutcomeUnknown => "outcome_unknown",
        }
    }
}

pub fn report_execution_params(elicitation_id: &str, execution: Execution) -> Value {
    json!({"elicitation_id": elicitation_id, "execution": execution.as_str()})
}

pub fn report_execution_with_reason(
    elicitation_id: &str,
    execution: Execution,
    reason: Option<ExecutionReason>,
) -> Value {
    let mut params = report_execution_params(elicitation_id, execution);
    if execution == Execution::ApprovedNotExecuted {
        if let Some(reason) = reason {
            params["reason"] = Value::from(reason.as_str());
        }
    }
    params
}

/// Whether `value` may be sent as `requester_ref`: 1 to 128 printable ASCII
/// characters (bytes 0x20 to 0x7e). Cingulate refuses anything else, and a
/// refused request is a card nobody sees, so an unfit key is left off rather
/// than sent.
pub fn is_requester_ref(value: &str) -> bool {
    (1..=128).contains(&value.len()) && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

/// Every refusal code a requester can receive: the shared transport codes and
/// the requester-specific ones of the v2 contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefusalCode {
    RequestTooLarge,
    InvalidEnvelope,
    UnknownMethod,
    ConsentUnavailable,
    StoreError,
    Cancelled,
    RequesterRefused,
    InvalidRequest,
    UnknownKind,
    FailClosedRequired,
    ConsentRetired,
    AccessNoHead,
    AccessUnavailable,
    NotOwner,
    NotFound,
    InvalidExecution,
    RequestConflict,
    Expired,
    /// A code this client does not know. Read as a failure of the call,
    /// never as a grant.
    Unknown(String),
}

impl RefusalCode {
    pub fn parse(code: &str) -> Self {
        match code {
            "elicitation_request_too_large" => Self::RequestTooLarge,
            "invalid_request" => Self::InvalidEnvelope,
            "unknown_method" => Self::UnknownMethod,
            "consent_unavailable" => Self::ConsentUnavailable,
            "elicitation_store_error" => Self::StoreError,
            "cancelled" => Self::Cancelled,
            "elicitation_requester_refused" => Self::RequesterRefused,
            "elicitation_invalid_request" => Self::InvalidRequest,
            "elicitation_unknown_kind" => Self::UnknownKind,
            "elicitation_fail_closed_required" => Self::FailClosedRequired,
            "consent_retired" => Self::ConsentRetired,
            "access_no_head" => Self::AccessNoHead,
            "access_unavailable" => Self::AccessUnavailable,
            "elicitation_not_owner" => Self::NotOwner,
            "elicitation_not_found" => Self::NotFound,
            "elicitation_invalid_execution" => Self::InvalidExecution,
            "elicitation_request_conflict" => Self::RequestConflict,
            "elicitation_expired" => Self::Expired,
            other => Self::Unknown(other.to_string()),
        }
    }
}

/// A refusal as Cingulate sent it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: RefusalCode,
    pub message: String,
}

impl Refusal {
    /// The refusal in an Error frame body, or `None` when the body is not
    /// shaped like one.
    pub fn from_error_body(body: &[u8]) -> Option<Self> {
        let value: Value = serde_json::from_slice(body).ok()?;
        Some(Self {
            code: RefusalCode::parse(value.get("code")?.as_str()?),
            message: value
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        })
    }
}

/// The `result` member of a success reply, or `None` when the reply has none.
pub fn result_of(body: &[u8]) -> Option<Value> {
    let mut value: Value = serde_json::from_slice(body).ok()?;
    value.get_mut("result").map(Value::take)
}

/// A card's lifecycle state as a requester record reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CardState {
    Pending,
    Answered,
    Expired,
    Withdrawn,
    /// A state this client does not know: never read as answered.
    Other(String),
}

/// The parts of a requester record the client branches on. The whole record
/// is kept in `raw` for callers that need more.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub elicitation_id: String,
    pub state: CardState,
    /// Present only on an answered card.
    pub answered_choice_id: Option<String>,
    pub requester_ref: Option<String>,
    /// Set by `consent.detach` on a pending card.
    pub detached: bool,
    pub raw: Value,
}

impl Record {
    /// A dedicated answer must name the one vault request this card filed.
    /// A generic Allow, a missing item, or a mismatched request_id never grants
    /// it. Allows also require a recognized duration and envelope-hash shape.
    pub fn secret_use_decision(&self, request_id: &str) -> Option<&'static str> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Answer {
            decision: String,
            duration: Option<String>,
            items: Vec<Item>,
            envelope_sha256: Option<String>,
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Item {
            request_id: String,
            decision: String,
        }
        let answer: Answer =
            serde_json::from_value(self.raw.get("secret_use_answer")?.clone()).ok()?;
        let [item] = answer.items.as_slice() else {
            return None;
        };
        if item.request_id != request_id || !matches!(item.decision.as_str(), "allow" | "decline") {
            return None;
        }
        match answer.decision.as_str() {
            "allow"
                if matches!(
                    answer.duration.as_deref(),
                    Some("once" | "hour" | "session" | "permanent")
                ) && answer.envelope_sha256.as_deref().is_some_and(|hash| {
                    hash.len() == 64
                        && hash
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                }) =>
            {
                Some(if item.decision == "allow" {
                    "allow"
                } else {
                    "decline"
                })
            }
            "decline"
                if item.decision == "decline"
                    && answer.duration.is_none()
                    && answer.envelope_sha256.is_none() =>
            {
                Some("decline")
            }
            _ => None,
        }
    }

    pub fn parse(value: Value) -> Option<Self> {
        let object: &Map<String, Value> = value.as_object()?;
        let elicitation_id = object.get("elicitation_id")?.as_str()?.to_string();
        let state = match object.get("state")?.as_str()? {
            "pending" => CardState::Pending,
            "answered" => CardState::Answered,
            "expired" => CardState::Expired,
            "withdrawn" => CardState::Withdrawn,
            other => CardState::Other(other.to_string()),
        };
        let text = |key: &str| object.get(key).and_then(Value::as_str).map(str::to_string);
        Some(Self {
            elicitation_id,
            state,
            answered_choice_id: text("answered_choice_id"),
            requester_ref: text("requester_ref"),
            detached: object.get("detached").and_then(Value::as_bool) == Some(true),
            raw: value,
        })
    }

    pub fn is_settled(&self) -> bool {
        !matches!(self.state, CardState::Pending)
    }
}

/// One page of `consent.answers`.
#[derive(Debug, Clone, PartialEq)]
pub struct AnswersPage {
    /// After 24 hours Cingulate replaces an unacknowledged answer with only its
    /// id, expired state and settlement time. This tombstone clears the local
    /// pending card as an answer lost; it contains no evidence of a choice.
    pub records: Vec<Record>,
    pub cursor: i64,
    /// Present on a partial page: pass it as the next `since`.
    pub continuation: Option<i64>,
}

impl AnswersPage {
    pub fn parse(value: &Value) -> Option<Self> {
        let records = value
            .get("records")?
            .as_array()?
            .iter()
            .filter_map(|row| Record::parse(row.clone()))
            .collect();
        Some(Self {
            records,
            cursor: value.get("cursor")?.as_i64()?,
            continuation: value.get("continuation").and_then(Value::as_i64),
        })
    }
}
