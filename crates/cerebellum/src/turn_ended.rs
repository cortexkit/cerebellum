//! The `session.turn_ended` management operation: a thin adapter that admits
//! and parses the call, then hands it to
//! [`Coordinator::turn_ended`](crate::computer_capability::cursor::Coordinator::turn_ended).
//!
//! Interim. Prefrontal core calls this directly today. The intended source is a
//! harness module publishing its `turn_ended` event on the event plane, with
//! cerebellum subscribing; when that lands, this adapter and core's direct call
//! are deleted and the subscription calls the same internal function. Nothing
//! behind the adapter needs to change. The parameters are exactly that event's
//! fields for the same reason.

use serde_json::{Map, Value};

use crate::computer_capability::cursor::TurnOutcome;

/// A parsed `session.turn_ended` call: what the internal function needs.
/// The other fields are checked for shape and then not used here.
pub(crate) struct TurnEnded {
    /// The harness runner's own session ref.
    pub(crate) session_ref: String,
    /// `scope.ref`: the daemon-stamped ref of the head's scope. Badges are
    /// matched on it alone, since a revived session keeps its ref but takes a
    /// new epoch.
    pub(crate) scope_ref: String,
    pub(crate) outcome: TurnOutcome,
    /// The event timestamp is the only request value exposed in health metrics.
    pub(crate) at_ms: u64,
}

/// Which parameter was refused, and why, for an `invalid_request` reply.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ParamsError {
    pub(crate) field: String,
    pub(crate) reason: &'static str,
}

/// Every accepted parameter. All are required except `error_class`.
const FIELDS: [&str; 10] = [
    "session_ref",
    "scope",
    "harness",
    "turn_id",
    "outcome",
    "error_class",
    "quality",
    "source",
    "seq",
    "at_ms",
];
const SCOPE_FIELDS: [&str; 3] = ["owner", "ref", "epoch"];
/// The longest `session_ref` accepted. Runner refs are well under this; the
/// cap only keeps an absurd value out of memory.
const SESSION_REF_MAX_BYTES: usize = 256;
const ERROR_CLASSES: [&str; 6] = [
    "provider_capacity",
    "provider_quota",
    "auth",
    "transport",
    "harness",
    "unknown",
];

fn error(field: &str, reason: &'static str) -> ParamsError {
    ParamsError {
        field: field.to_string(),
        reason,
    }
}

/// Refuse the alphabetically first field outside `allowed`, so the reply is
/// the same whatever order the caller's JSON object had.
fn unknown_field(
    object: &Map<String, Value>,
    allowed: &[&str],
    prefix: &str,
) -> Result<(), ParamsError> {
    match object
        .keys()
        .filter(|field| !allowed.contains(&field.as_str()))
        .min()
    {
        Some(field) => Err(error(&format!("{prefix}{field}"), "unknown_field")),
        None => Ok(()),
    }
}

fn present<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    name: &str,
) -> Result<&'a Value, ParamsError> {
    object
        .get(field)
        .ok_or_else(|| error(name, "missing_field"))
}

fn string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    name: &str,
) -> Result<&'a str, ParamsError> {
    present(object, field, name)?
        .as_str()
        .ok_or_else(|| error(name, "wrong_type"))
}

fn unsigned(object: &Map<String, Value>, field: &str, name: &str) -> Result<u64, ParamsError> {
    present(object, field, name)?
        .as_u64()
        .ok_or_else(|| error(name, "wrong_type"))
}

/// Parameters are exactly `{session_ref, scope: {owner, ref, epoch}, harness,
/// turn_id, outcome, error_class?, quality, source, seq, at_ms}`. Every field
/// but `error_class` is required and no other field is accepted, so a caller
/// that sends something this module does not understand hears about it
/// instead of being ignored. A refusal names the field, with nested scope
/// fields as `scope.<name>`.
pub(crate) fn parse(params: &Map<String, Value>) -> Result<TurnEnded, ParamsError> {
    unknown_field(params, &FIELDS, "")?;
    let session_ref = string(params, "session_ref", "session_ref")?;
    // The harness runner's ref is opaque here: badges match on `scope.ref`, and
    // this value is only carried. Its spelling belongs to the runner and has
    // changed between runner releases, so any short printable ASCII token is
    // taken as given. Control characters, spaces and oversized values are
    // still refused, because no runner sends them.
    if session_ref.is_empty()
        || session_ref.len() > SESSION_REF_MAX_BYTES
        || !session_ref.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(error("session_ref", "invalid_value"));
    }
    let scope = present(params, "scope", "scope")?
        .as_object()
        .ok_or_else(|| error("scope", "wrong_type"))?;
    unknown_field(scope, &SCOPE_FIELDS, "scope.")?;
    let owner = present(scope, "owner", "scope.owner")?;
    let scope_ref = string(scope, "ref", "scope.ref")?.to_string();
    let epoch = unsigned(scope, "epoch", "scope.epoch")?;
    // The owner is read with the protocol's own scope type, so it accepts
    // exactly the principal shapes the daemon stamps on scopes.
    let stamped = serde_json::json!({"owner": owner, "ref": scope_ref, "scope_epoch": epoch});
    if serde_json::from_value::<subc_protocol::scope::ScopeParent>(stamped).is_err() {
        return Err(error("scope.owner", "invalid_value"));
    }
    string(params, "harness", "harness")?;
    // An opaque token from whoever reports the turn (core's stopgap sends its
    // own, the harness event 32 hex digits). Only its bounds are checked; it
    // is never parsed, stored or matched on.
    let turn_id = string(params, "turn_id", "turn_id")?;
    if turn_id.is_empty()
        || turn_id.len() > 128
        || !turn_id.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
    {
        return Err(error("turn_id", "invalid_value"));
    }
    let outcome = match string(params, "outcome", "outcome")? {
        "completed" => TurnOutcome::Completed,
        "stopped" => TurnOutcome::Stopped,
        "failed" => TurnOutcome::Failed,
        _ => return Err(error("outcome", "invalid_value")),
    };
    // Optional, and only meaningful for a failed turn: on any other outcome
    // it would describe a failure that did not happen, so it is refused.
    if params.contains_key("error_class") {
        let class = string(params, "error_class", "error_class")?;
        if outcome != TurnOutcome::Failed || !ERROR_CLASSES.contains(&class) {
            return Err(error("error_class", "invalid_value"));
        }
    }
    if !matches!(
        string(params, "quality", "quality")?,
        "strong" | "weak" | "none"
    ) {
        return Err(error("quality", "invalid_value"));
    }
    string(params, "source", "source")?;
    unsigned(params, "seq", "seq")?;
    // The timestamp is retained for health visibility; the handler still hides
    // the badge as soon as the call arrives, whenever the turn actually ended.
    let at_ms = unsigned(params, "at_ms", "at_ms")?;
    Ok(TurnEnded {
        session_ref: session_ref.to_string(),
        scope_ref,
        outcome,
        at_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SESSION: &str = "0123456789abcdef0123456789abcdef";

    fn full() -> Value {
        json!({
            "session_ref": SESSION,
            "scope": {"owner": {"kind": "reserved", "module_id": "prefrontal-core"}, "ref": "s-1", "epoch": 3},
            "harness": "claude-code",
            "turn_id": "t-1",
            "outcome": "completed",
            "quality": "strong",
            "source": "stop-hook",
            "seq": 7,
            "at_ms": 1_700_000_000_000u64,
        })
    }

    fn refused(params: Value) -> (String, &'static str) {
        match parse(params.as_object().unwrap()) {
            Ok(_) => panic!("accepted"),
            Err(error) => (error.field, error.reason),
        }
    }

    #[test]
    fn turn_ended_params_accept_every_agreed_outcome_and_quality() {
        for (wire, outcome) in [
            ("completed", TurnOutcome::Completed),
            ("stopped", TurnOutcome::Stopped),
            ("failed", TurnOutcome::Failed),
        ] {
            for quality in ["strong", "weak", "none"] {
                let mut params = full();
                params["outcome"] = json!(wire);
                params["quality"] = json!(quality);
                let request = parse(params.as_object().unwrap()).unwrap();
                assert_eq!(request.session_ref, SESSION);
                assert_eq!(request.scope_ref, "s-1");
                assert_eq!(request.outcome, outcome);
            }
        }
        for class in ERROR_CLASSES {
            let mut params = full();
            params["outcome"] = json!("failed");
            params["error_class"] = json!(class);
            assert!(parse(params.as_object().unwrap()).is_ok(), "{class}");
        }
    }

    #[test]
    fn turn_id_is_an_opaque_bounded_printable_token() {
        for token in [
            "t".to_string(),
            "x".repeat(128),
            "0123456789abcdef0123456789abcdef".to_string(),
            "core stopgap/42:~".to_string(),
        ] {
            let mut params = full();
            params["turn_id"] = json!(token);
            assert!(parse(params.as_object().unwrap()).is_ok(), "{token}");
        }
    }

    #[test]
    fn error_class_is_refused_unless_the_turn_failed() {
        for outcome in ["completed", "stopped"] {
            let mut params = full();
            params["outcome"] = json!(outcome);
            params["error_class"] = json!("auth");
            assert_eq!(refused(params), ("error_class".into(), "invalid_value"));
        }
        let mut params = full();
        params["outcome"] = json!("failed");
        params["error_class"] = json!("cosmic_rays");
        assert_eq!(refused(params), ("error_class".into(), "invalid_value"));
        let mut params = full();
        params["outcome"] = json!("failed");
        params["error_class"] = json!(null);
        assert_eq!(refused(params), ("error_class".into(), "wrong_type"));
    }

    #[test]
    fn turn_ended_params_name_the_refused_field() {
        for field in FIELDS.into_iter().filter(|field| *field != "error_class") {
            let mut missing = full();
            missing.as_object_mut().unwrap().remove(field);
            assert_eq!(refused(missing), (field.to_string(), "missing_field"));
        }
        for field in SCOPE_FIELDS {
            let mut missing = full();
            missing["scope"].as_object_mut().unwrap().remove(field);
            assert_eq!(
                refused(missing),
                (format!("scope.{field}"), "missing_field")
            );
        }
        let mut extra = full();
        extra["ended_at_ms"] = json!(1);
        assert_eq!(refused(extra), ("ended_at_ms".into(), "unknown_field"));
        let mut extra = full();
        extra["scope"]["kind"] = json!("head");
        assert_eq!(refused(extra), ("scope.kind".into(), "unknown_field"));
        for (field, value, reason) in [
            ("session_ref", json!(""), "invalid_value"),
            (
                "session_ref",
                json!("runner/harness session"),
                "invalid_value",
            ),
            (
                "session_ref",
                json!("x".repeat(SESSION_REF_MAX_BYTES + 1)),
                "invalid_value",
            ),
            ("session_ref", json!("tab\there"), "invalid_value"),
            ("session_ref", json!(7), "wrong_type"),
            ("outcome", json!("paused"), "invalid_value"),
            ("quality", json!("certain"), "invalid_value"),
            ("at_ms", json!(-1), "wrong_type"),
            ("seq", json!(-1), "wrong_type"),
            ("seq", json!("7"), "wrong_type"),
            ("harness", json!(7), "wrong_type"),
            ("turn_id", json!(null), "wrong_type"),
            ("turn_id", json!(""), "invalid_value"),
            ("turn_id", json!("t".repeat(129)), "invalid_value"),
            ("turn_id", json!("turn\n1"), "invalid_value"),
            ("turn_id", json!("tür-1"), "invalid_value"),
            ("source", json!(["x"]), "wrong_type"),
            ("scope", json!("s-1"), "wrong_type"),
        ] {
            let mut params = full();
            params[field] = value;
            assert_eq!(refused(params), (field.to_string(), reason));
        }
        let mut owner = full();
        owner["scope"]["owner"] = json!({"kind": "planted"});
        assert_eq!(refused(owner), ("scope.owner".into(), "invalid_value"));
        let mut epoch = full();
        epoch["scope"]["epoch"] = json!("3");
        assert_eq!(refused(epoch), ("scope.epoch".into(), "wrong_type"));
    }
}
