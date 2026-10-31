//! Closed request and response helpers for browser session control.

use serde_json::{json, Value};

use cerebellum_core::identity::RouteIdentity;

/// Compatibility entry point for schema-focused callers without a live route.
pub fn handle_browser_status(params: &Value) -> Value {
    handle_browser_status_for_identity(params, &placeholder_identity_for_schema_tests())
}

/// A status read validates only its closed request schema. Live dispatch replaces
/// `no_session` with the route-owned lifecycle snapshot after this validation.
pub fn handle_browser_status_for_identity(params: &Value, _identity: &RouteIdentity) -> Value {
    if let Some(object) = params.as_object() {
        if let Some(field) = object.keys().min() {
            return invalid_request(field, "unknown_field");
        }
    } else {
        return invalid_request("$", "wrong_type");
    }
    json!({"outcome": "no_session"})
}

pub fn invalid_request(field: &str, reason_code: &str) -> Value {
    json!({
        "outcome": "invalid_request",
        "detail": {
            "field": field,
            "reason_code": reason_code,
        },
    })
}

fn placeholder_identity_for_schema_tests() -> RouteIdentity {
    RouteIdentity::from_accepted_bind(
        &subc_protocol::BindIdentity::new("legacy".to_string(), "legacy-session".to_string()),
        &None,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_status_is_no_session_without_legacy_context() {
        assert_eq!(
            handle_browser_status(&json!({})),
            json!({"outcome": "no_session"})
        );
    }

    #[test]
    fn invalid_status_uses_the_common_closed_shape() {
        assert_eq!(
            handle_browser_status(&json!({"z": 1, "a": 2})),
            invalid_request("a", "unknown_field")
        );
        assert_eq!(
            handle_browser_status(&Value::Null),
            invalid_request("$", "wrong_type")
        );
    }
}
