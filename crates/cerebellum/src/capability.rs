//! The `browser.status` capability.
//!
//! `execution_mode: pure` — no observable side effect (reports profile
//! disposition without opening a browser).
//!
//! Request: `{}` (empty; unknown fields rejected — closed schema).
//! Result: `{ outcome, context, session: null | { url: string|null, ready: bool } }`.
//!
//! `context` carries module-resolved facts only (never an echo of caller-supplied
//! bind identity, which subc already correlates by (channel, corr)):
//! `{ profile_uuid: string|null, profile_name: string,
//! session_kind_effective: "primary"|"subagent"|"ephemeral",
//! profile_disposition: "durable"|"disposable"|"none" }`.
//!
//! Outcomes: `ok`, `no_session`, `invalid_request`, `internal_error`. In Spec A,
//! absent a browser, a bound session with no browsing context returns `no_session`
//! with a resolved `context`. `invalid_request` is the application-level
//! closed-schema rejection — the module parses the body, so an unknown-field
//! request is rejected in the response body's outcome enum, never via the
//! transport Error frame.

use serde_json::{json, Value};

use crate::identity::{ProfileDisposition, SessionKind};

/// The `browser.status` result body (flat, no `{result}` wrapper).
#[derive(Debug, Clone, serde::Serialize)]
struct BrowserStatusResult {
    outcome: &'static str,
    context: BrowserStatusContext,
    session: Option<BrowserSession>,
}

/// The module-resolved context. Never echoes caller-supplied bind identity.
#[derive(Debug, Clone, serde::Serialize)]
struct BrowserStatusContext {
    profile_uuid: Option<String>,
    profile_name: String,
    session_kind_effective: &'static str,
    profile_disposition: &'static str,
}

/// The session state. `null` when there is no browsing context (Spec A always).
#[derive(Debug, Clone, serde::Serialize)]
struct BrowserSession {
    url: Option<String>,
    ready: bool,
}

/// Handle a `browser.status` request. The `params` value is the parsed request
/// body's `params` field (or `{}` when absent).
///
/// Returns a flat JSON result body (`{ outcome, context, session }`) suitable
/// for a normal Response frame. The subc Error frame stays purely
/// transport/routing — schema violations are application-level.
pub fn handle_browser_status(params: &Value) -> Value {
    // Closed schema: the request is `{}` (empty). Unknown fields are rejected at
    // the application level with `outcome: invalid_request` and a detail
    // `{ field, reason_code: "unknown_field" }`.
    if let Some(obj) = params.as_object() {
        if !obj.is_empty() {
            let field = obj.keys().next().expect("non-empty object has a key");
            return json!({
                "outcome": "invalid_request",
                "context": null,
                "session": null,
                "detail": {
                    "field": field,
                    "reason_code": "unknown_field",
                },
            });
        }
    } else {
        // params is not an object at all (e.g. null, string, number).
        return json!({
            "outcome": "invalid_request",
            "context": null,
            "session": null,
            "detail": {
                "field": "params",
                "reason_code": "expected_object",
            },
        });
    }

    // In Spec A there is no browser, so a bound session with no browsing context
    // returns `no_session` with a resolved `context`. The session_kind_effective
    // and profile_disposition are resolved from the alfonso-core-stamped
    // sessionKind (defaulted to `primary` in this slice; Spec B threads the real
    // stamped value from the bind).
    let session_kind = SessionKind::Primary;
    let disposition = ProfileDisposition::for_session_kind(session_kind);

    let result = BrowserStatusResult {
        outcome: "no_session",
        context: BrowserStatusContext {
            // No profile storage in Spec A — profile_uuid is absent.
            profile_uuid: None,
            // The profile name is derived from the agentProjectId + sessionKind
            // in Spec B; in Spec A it is a stable placeholder.
            profile_name: "default".to_string(),
            session_kind_effective: session_kind.as_str(),
            profile_disposition: disposition.as_str(),
        },
        // No browsing context in Spec A.
        session: None,
    };

    serde_json::to_value(result).unwrap_or_else(|_| {
        json!({
            "outcome": "internal_error",
            "context": null,
            "session": null,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_request_returns_no_session_with_resolved_context() {
        let result = handle_browser_status(&json!({}));
        assert_eq!(result["outcome"], "no_session");
        let context = &result["context"];
        assert!(context.is_object(), "context must be resolved");
        assert_eq!(context["session_kind_effective"], "primary");
        assert_eq!(context["profile_disposition"], "durable");
        assert_eq!(context["profile_uuid"], serde_json::Value::Null);
        assert!(context["profile_name"].is_string());
        assert_eq!(result["session"], serde_json::Value::Null);
    }

    #[test]
    fn unknown_field_returns_invalid_request_with_field_detail() {
        let result = handle_browser_status(&json!({ "unexpected": true }));
        assert_eq!(result["outcome"], "invalid_request");
        assert_eq!(result["detail"]["field"], "unexpected");
        assert_eq!(result["detail"]["reason_code"], "unknown_field");
        assert_eq!(result["session"], serde_json::Value::Null);
    }

    #[test]
    fn multiple_unknown_fields_report_first_field() {
        let result = handle_browser_status(&json!({ "a": 1, "b": 2 }));
        assert_eq!(result["outcome"], "invalid_request");
        assert_eq!(result["detail"]["reason_code"], "unknown_field");
        // The first key is reported (deterministic).
        let field = result["detail"]["field"].as_str().unwrap();
        assert!(
            field == "a" || field == "b",
            "field should be one of the keys"
        );
    }

    #[test]
    fn non_object_params_returns_invalid_request() {
        let result = handle_browser_status(&json!("not an object"));
        assert_eq!(result["outcome"], "invalid_request");
        assert_eq!(result["detail"]["field"], "params");
        assert_eq!(result["detail"]["reason_code"], "expected_object");
    }

    #[test]
    fn result_does_not_echo_conversation_key_or_agent_project_id() {
        // The result context carries module-resolved facts only, never an echo
        // of caller-supplied bind identity.
        let result = handle_browser_status(&json!({}));
        let context = &result["context"];
        let context_str = context.to_string();
        assert!(
            !context_str.contains("conversation") && !context_str.contains("session-"),
            "context must not echo the conversation-key: {context_str}"
        );
        assert!(
            !context_str.contains("agentProjectId") && !context_str.contains("pj-"),
            "context must not echo the agentProjectId: {context_str}"
        );
    }

    #[test]
    fn result_body_is_flat_no_result_wrapper() {
        // The subc data plane treats the response body as opaque bytes, so the
        // flat `{ outcome, context, ... }` result body is cerebellum's own
        // contract with first-party callers (no `{result}` wrapper).
        let result = handle_browser_status(&json!({}));
        assert!(result.get("result").is_none(), "no {{result}} wrapper");
        assert!(result.get("outcome").is_some(), "flat outcome field");
    }
}
