use serde_json::Value;

/// Prefer protocol `code` or tool `errorCode`; raw tool-body `outcome` values
/// such as `login_observed` are mapped to `ok` using the tool-result success rules.
pub(crate) fn outcome(body: &Value, error_frame: bool) -> &str {
    if error_frame {
        return body["code"]
            .as_str()
            .filter(|code| !code.is_empty())
            .unwrap_or("unknown");
    }
    if let Some(code) = body["errorCode"].as_str().filter(|code| !code.is_empty()) {
        return code;
    }
    if body["isError"] == true {
        return "unknown";
    }
    if body["isError"] == false {
        return "ok";
    }
    let structured = body.get("structuredContent").unwrap_or(body);
    match structured["outcome"].as_str() {
        Some("unknown" | "outcome_unknown") | None => "unknown",
        Some(code) if crate::tool_result::is_success(code) => "ok",
        Some("") => "unknown",
        Some(code) => code,
    }
}
