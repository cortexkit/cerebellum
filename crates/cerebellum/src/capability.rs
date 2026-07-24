//! The `browser.status` capability.
//!
//! `execution_mode: pure` — no observable side effect (reports profile
//! disposition without opening a browser).
//!
//! Request: `{}` (empty; unknown fields rejected — closed schema).
//! Result: `{ outcome, context, session: null | { url: string|null, ready: bool } }`.
//!
//! `context` carries module-resolved facts only (never an echo of caller-supplied
//! bind identity because the surrounding daemon already correlates each request
//! using its channel and correlation ID.

use serde_json::{json, Value};

use cerebellum_core::identity::{ProfileResolution, RouteIdentity, SessionKind};

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
    profile_name: Option<String>,
    session_kind_effective: &'static str,
    profile_disposition: &'static str,
}

/// The session state. `null` when there is no browsing context (Spec A always).
#[derive(Debug, Clone, serde::Serialize)]
struct BrowserSession {
    url: Option<String>,
    ready: bool,
}

/// Handle a `browser.status` request without a bound route. This compatibility
/// entry point is useful for the closed-schema unit tests; live dispatch uses
/// [`handle_browser_status_for_identity`] after route.bind has been accepted.
pub fn handle_browser_status(params: &Value) -> Value {
    // Live dispatch always uses handle_browser_status_for_identity with real bind
    // facts; this placeholder exists only to support schema-focused tests.
    handle_browser_status_for_identity(params, &placeholder_identity_for_schema_tests())
}

/// Handle `browser.status` using the identity retained from an accepted bind.
/// The request contributes only its closed-schema parameters; identity and
/// profile policy come exclusively from the bind facts.
pub fn handle_browser_status_for_identity(params: &Value, identity: &RouteIdentity) -> Value {
    // Closed schema: the request is `{}` (empty). Unknown fields are rejected at
    // the application level with `outcome: invalid_request` and a detail
    // `{ field, reason_code: "unknown_field" }`.
    if let Some(obj) = params.as_object() {
        if !obj.is_empty() {
            // Select explicitly rather than relying on serde_json's map
            // implementation: the closed-schema contract reports the
            // lexicographically smallest unknown property.
            let field = obj.keys().min().expect("non-empty object has a key");
            return invalid_request(field, "unknown_field");
        }
    } else {
        // The capability request itself must be an object. `$` identifies the
        // top-level value when it is null, an array, string, number, or boolean.
        return invalid_request("$", "wrong_type");
    }

    // This is policy-only resolution. It computes a logical key but does not
    // consult profile storage or launch a browser.
    let resolution = identity.resolve_profile();
    let result = BrowserStatusResult {
        outcome: "no_session",
        context: context_for(identity.session_kind, &resolution),
        // No browsing context exists in this browser-free slice.
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

fn invalid_request(field: &str, reason_code: &str) -> Value {
    json!({
        "outcome": "invalid_request",
        "context": null,
        "session": null,
        "detail": {
            "field": field,
            "reason_code": reason_code,
        },
    })
}

fn context_for(kind: SessionKind, resolution: &ProfileResolution) -> BrowserStatusContext {
    BrowserStatusContext {
        // No profile storage in this slice — profile_uuid is absent.
        profile_uuid: None,
        profile_name: resolution.profile_name.clone(),
        session_kind_effective: kind.as_str(),
        profile_disposition: resolution.profile_disposition.as_str(),
    }
}

fn placeholder_identity_for_schema_tests() -> RouteIdentity {
    RouteIdentity::from_accepted_bind(
        &subc_protocol::BindIdentity {
            project_root: std::path::PathBuf::from("/legacy/project"),
            harness: "legacy".to_string(),
            session: "legacy-session".to_string(),
        },
        &None,
        None,
    )
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
        assert_eq!(context["profile_name"], "default");
        assert_eq!(result["session"], serde_json::Value::Null);
    }

    #[test]
    fn identity_resolution_changes_context_without_opening_storage() {
        let identity = RouteIdentity::from_accepted_bind(
            &subc_protocol::BindIdentity {
                project_root: std::path::PathBuf::from("/tmp/project"),
                harness: "opencode".to_string(),
                session: "conversation-1".to_string(),
            },
            &Some(subc_protocol::Principal::Direct),
            Some(&json!({
                "agentProjectId": "pj-project",
                "sessionKind": "subagent",
            })),
        );
        let result = handle_browser_status_for_identity(&json!({}), &identity);
        assert_eq!(result["outcome"], "no_session");
        assert_eq!(result["context"]["session_kind_effective"], "subagent");
        assert_eq!(result["context"]["profile_disposition"], "disposable");
        assert_eq!(result["context"]["profile_name"], "default");
        assert_eq!(result["context"]["profile_uuid"], Value::Null);
        assert!(!result.to_string().contains("pj-project"));
        assert!(!result.to_string().contains("conversation-1"));
    }

    #[test]
    fn ephemeral_context_has_null_profile_name() {
        let identity = RouteIdentity::from_accepted_bind(
            &subc_protocol::BindIdentity {
                project_root: std::path::PathBuf::from("/tmp/project"),
                harness: "opencode".to_string(),
                session: "conversation-1".to_string(),
            },
            &Some(subc_protocol::Principal::Direct),
            Some(&json!({
                "agentProjectId": "pj-project",
                "sessionKind": "ephemeral",
            })),
        );
        let result = handle_browser_status_for_identity(&json!({}), &identity);
        assert_eq!(result["context"]["profile_disposition"], "none");
        assert_eq!(result["context"]["profile_name"], Value::Null);
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
    fn multiple_unknown_fields_report_lexicographically_smallest_field() {
        let result = handle_browser_status(&json!({ "zebra": 1, "alpha": 2, "middle": 3 }));
        assert_eq!(result["outcome"], "invalid_request");
        assert_eq!(result["detail"]["field"], "alpha");
        assert_eq!(result["detail"]["reason_code"], "unknown_field");
    }

    #[test]
    fn top_level_non_objects_return_wrong_type_detail() {
        for value in [
            Value::Null,
            json!([]),
            json!("not an object"),
            json!(42),
            json!(true),
        ] {
            let result = handle_browser_status(&value);
            assert_eq!(result["outcome"], "invalid_request");
            assert_eq!(result["detail"]["field"], "$");
            assert_eq!(result["detail"]["reason_code"], "wrong_type");
            assert_eq!(result["context"], Value::Null);
            assert_eq!(result["session"], Value::Null);
        }
    }

    #[test]
    fn result_does_not_echo_conversation_key_or_agent_project_id() {
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
        let result = handle_browser_status(&json!({}));
        assert!(result.get("result").is_none(), "no {{result}} wrapper");
        assert!(result.get("outcome").is_some(), "flat outcome field");
    }
}
