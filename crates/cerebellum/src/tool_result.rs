//! Model-facing projection belongs to the provider; structured replies retain
//! the identifiers and outcomes programs need without repeating image bytes in text.

use crate::ModuleError;
use cortexkit_role_tool_provider::result::{self, ContentPart, ImageContent, ToolResult};
use serde_json::{json, Map, Value};

tokio::task_local! {
    pub(crate) static CONTENT_V1: bool;
}

fn notice(id: Option<&str>, reason: &str) -> String {
    format!(
        "Image {} was not delivered: {reason}",
        id.unwrap_or("unknown id")
    )
}

fn compact_members(members: impl IntoIterator<Item = (String, Value)>) -> String {
    let members = members
        .into_iter()
        .map(|(key, value)| {
            format!(
                "{}:{}",
                serde_json::to_string(&key).expect("key serializes"),
                value
            )
        })
        .collect::<Vec<_>>();
    format!("{{{}}}", members.join(","))
}

fn image_projection(value: &Value) -> (String, Option<ImageContent>, Option<String>) {
    let mut descriptor = value
        .as_object()
        .cloned()
        .unwrap_or_else(|| Map::from_iter([("descriptor".into(), value.clone())]));
    let data = descriptor.remove("data_b64");
    let id = descriptor
        .get("image_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mime = descriptor.get("mime").and_then(Value::as_str);
    let dimension = |key: &str| {
        descriptor
            .get(&format!("{key}_px"))
            .or_else(|| descriptor.get(key))
            .and_then(Value::as_u64)
            .filter(|value| *value > 0 && *value <= 9_007_199_254_740_991)
    };
    let mut image = None;
    let reason = if !value.is_object() {
        Some("invalid_image_shape")
    } else if data
        .as_ref()
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        Some("inline_bytes_missing")
    } else if !matches!(
        mime,
        Some("image/png" | "image/jpeg" | "image/webp" | "image/gif")
    ) {
        Some("unsupported_mime")
    } else if let (Some(width), Some(height)) = (dimension("width"), dimension("height")) {
        let mut candidate = ImageContent::new(
            mime.unwrap(),
            data.as_ref().unwrap().as_str().unwrap(),
            width,
            height,
        )
        .with_alt(notice(id.as_deref(), "image_delivery_unavailable"));
        candidate.id = id.clone();
        // The contract validates padding and trailing bits as well as the alphabet.
        // A malformed image becomes an explicit notice, never a consumer crash.
        let probe = ToolResult::new(vec![ContentPart::image(candidate.clone())]);
        match result::validate(&probe) {
            Err(problem) if problem.member.ends_with(".data") => Some("invalid_base64"),
            _ => {
                image = Some(candidate);
                None
            }
        }
    } else {
        Some("invalid_image_shape")
    };
    let mut members = descriptor.into_iter().collect::<Vec<_>>();
    if let Some(reason) = reason {
        // JSON.stringify preserves existing key positions and appends new ones.
        // Preserve that ordering in the legacy descriptor's model-facing text.
        for (key, value) in [
            ("delivery_status", json!("not_delivered")),
            ("delivery_reason", json!(reason)),
        ] {
            if let Some(member) = members.iter_mut().find(|(name, _)| name == key) {
                member.1 = value;
            } else {
                members.push((key.into(), value));
            }
        }
    }
    (
        compact_members(members),
        image,
        reason.map(|reason| notice(id.as_deref(), reason)),
    )
}

fn is_success(code: &str) -> bool {
    matches!(
        code,
        "ok" | "completed"
            | "ready"
            | "terminal"
            | "launched"
            | "already_running"
            | "launched_no_window"
            | "closed"
            | "captured"
            | "imported"
            | "presented"
            | "login_pending"
            | "login_observed"
            | "closed_by_caller"
            | "resumed"
            | "revoked"
            | "nothing_to_revoke"
            | "granted"
            | "created"
            | "updated"
            | "predicate_satisfied"
            | "timeout"
            | "installed_list_partial"
    )
}

fn project(reply: Value) -> ToolResult {
    let Some(object) = reply.as_object() else {
        return ToolResult::new(vec![ContentPart::text(reply.to_string())]);
    };
    let mut content = Vec::new();
    if let Some(state) = object.get("state_text").and_then(Value::as_str) {
        content.push(ContentPart::text(state));
    }
    let projected_image = object.get("image").map(image_projection);
    // State and notices are verbatim. Metadata uses serde_json instead of
    // emulating JSON.stringify: integral floats retain .0, negative zero and
    // exponent formatting can differ, and numeric keys keep serde_json order.
    // These host-formatting differences never alter the state or notice parts.
    let mut members = Vec::new();
    for (key, value) in object {
        if key == "state_text" && value.is_string() {
            continue;
        }
        let value = if key == "image" {
            projected_image.as_ref().unwrap().0.clone()
        } else {
            value.to_string()
        };
        members.push(format!(
            "{}:{value}",
            serde_json::to_string(key).expect("key serializes")
        ));
    }
    content.push(ContentPart::text(format!("{{{}}}", members.join(","))));
    let image = projected_image.and_then(|(_, image, note)| {
        if let Some(note) = note {
            content.push(ContentPart::text(note));
        }
        image
    });
    let mut result = ToolResult::new(content).with_structured_content(object.clone());
    if let Some(code) = object
        .get("outcome")
        .and_then(Value::as_str)
        .filter(|code| !is_success(code))
    {
        result = result.with_error(code);
        if let Some(remedy) = object.get("remedy").and_then(Value::as_str) {
            result.content.push(ContentPart::text(remedy));
        }
    }
    if let Some(image) = image {
        result.content.push(ContentPart::image(image));
    }
    result
}

fn strip_inline_image(result: &mut ToolResult, reason: &str) -> Option<String> {
    let image = result
        .structured_content
        .as_mut()?
        .get_mut("image")?
        .as_object_mut()?;
    image.remove("data_b64")?;
    let id = image
        .get("image_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    image.insert("delivery_status".into(), json!("not_delivered"));
    image.insert("delivery_reason".into(), json!(reason));
    Some(notice(id.as_deref(), reason))
}

pub(crate) fn encode(reply: Value) -> Result<Vec<u8>, ModuleError> {
    let mut result = project(reply);
    loop {
        let bytes = serde_json::to_vec(&result).map_err(ModuleError::Json)?;
        if bytes.len() < result::MAX_RESULT_BYTES {
            result::validate(&result).map_err(|problem| {
                ModuleError::Message(format!("invalid content/v1 result: {problem}"))
            })?;
            return Ok(bytes);
        }
        // Drop attachments last-first, including the copy programs would receive.
        // Keep all model-facing text, with an explicit notice for each omission.
        if let Some(index) = result
            .content
            .iter()
            .rposition(|part| matches!(part, ContentPart::Image(_)))
        {
            let ContentPart::Image(image) = result.content.remove(index) else {
                unreachable!()
            };
            strip_inline_image(&mut result, "reply_size_limit");
            result.content.insert(
                index,
                ContentPart::text(notice(image.id.as_deref(), "reply_size_limit")),
            );
        } else if strip_inline_image(&mut result, "reply_size_limit").is_some() {
            // Invalid images were already described as undelivered in content.
            // Their original inline bytes must not bypass the total reply bound.
        } else {
            let remedy = "the reply exceeds the content/v1 byte limit even without images; request a smaller state snapshot";
            result = ToolResult::new(vec![ContentPart::text(remedy)])
                .with_structured_content(Map::from_iter([
                    ("outcome".into(), json!("result_too_large")),
                    ("remedy".into(), json!(remedy)),
                ]))
                .with_error("result_too_large");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decoded(reply: Value) -> Value {
        serde_json::from_slice(&encode(reply).unwrap()).unwrap()
    }

    #[test]
    fn snapshot_state_text_is_verbatim_first_part() {
        let reply = json!({"outcome":"ok", "state_text":"article\n  r1 link \"quoted\" — café", "snapshot_id":"snap-1"});
        let result = decoded(reply.clone());
        assert_eq!(
            result["content"][0],
            json!({"type":"text", "text":"article\n  r1 link \"quoted\" — café"})
        );
        assert_eq!(
            result["content"][1]["text"],
            r#"{"outcome":"ok","snapshot_id":"snap-1"}"#
        );
        assert_eq!(result["structuredContent"], reply);
        assert!(result.get("isError").is_none());
    }

    fn read_state_reply() -> Value {
        json!({"outcome":"ok", "state_text":"app\n  e1 button Save", "image":{"data_b64":"AA==", "mime":"image/png", "width_px":12, "height_px":8, "image_id":"image-1"}})
    }

    #[test]
    fn read_state_image_follows_the_text() {
        let reply = read_state_reply();
        let result = decoded(reply.clone());
        assert_eq!(
            result["content"][0],
            json!({"type":"text", "text":"app\n  e1 button Save"})
        );
        assert_eq!(
            result["content"][1],
            json!({"type":"text", "text":r#"{"image":{"height_px":8,"image_id":"image-1","mime":"image/png","width_px":12},"outcome":"ok"}"#})
        );
        assert_eq!(
            result["content"][2],
            json!({"type":"image", "data":"AA==", "mimeType":"image/png", "width":12, "height":8, "id":"image-1", "alt":"Image image-1 was not delivered: image_delivery_unavailable"})
        );
        assert_eq!(result["structuredContent"], reply);
    }

    #[test]
    fn refusal_has_error_code_and_verbatim_remedy() {
        let result = decoded(
            json!({"outcome":"consent_unavailable", "detail":{"reason":"agent_run"}, "remedy":"an agent run cannot ask a person"}),
        );
        assert_eq!(result["isError"], true);
        assert_eq!(result["errorCode"], "consent_unavailable");
        assert_eq!(
            result["content"][1],
            json!({"type":"text", "text":"an agent run cannot ask a person"})
        );
    }

    #[test]
    fn invalid_base64_is_undelivered_text_not_a_crash() {
        let mut reply = read_state_reply();
        reply["image"]["data_b64"] = json!("AB==");
        let result = decoded(reply);
        assert_eq!(
            result["content"][2],
            json!({"type":"text", "text":"Image image-1 was not delivered: invalid_base64"})
        );
        assert!(!result["content"]
            .as_array()
            .unwrap()
            .iter()
            .any(|part| part["type"] == "image"));
        assert!(result["content"][1]["text"].as_str().unwrap().ends_with(r#""delivery_status":"not_delivered","delivery_reason":"invalid_base64"},"outcome":"ok"}"#));
    }

    #[test]
    fn oversized_image_is_dropped_but_text_is_kept() {
        let mut reply = read_state_reply();
        reply["image"]["data_b64"] = json!("AAAA".repeat(400_000));
        let result = decoded(reply);
        assert_eq!(result["content"][0]["text"], "app\n  e1 button Save");
        assert_eq!(
            result["content"][2],
            json!({"type":"text", "text":"Image image-1 was not delivered: reply_size_limit"})
        );
        assert!(result["structuredContent"]["image"]
            .get("data_b64")
            .is_none());
        assert_eq!(
            result["structuredContent"]["image"]["delivery_reason"],
            "reply_size_limit"
        );
        assert!(serde_json::to_vec(&result).unwrap().len() < 3 * 1024 * 1024);
    }

    #[test]
    fn oversized_text_is_refused_by_name_not_truncated() {
        let result =
            decoded(json!({"outcome":"ok", "state_text":"x".repeat(result::MAX_RESULT_BYTES)}));
        assert_eq!(result["errorCode"], "result_too_large");
        assert_eq!(result["isError"], true);
    }

    #[test]
    fn state_and_notice_bytes_are_independent_of_numeric_metadata() {
        let state = "article\n  r1 link \"quoted\" — café\t終";
        let reply = json!({"outcome":"completed", "state_text":state,
            "position":{"x":1.0,"y":-0.0,"scale":1e-7},
            "image":{"image_id":"reference-1", "mime":"image/png", "width_px":1,"height_px":1}});
        let result = decoded(reply);
        assert_eq!(
            result["content"][0]["text"].as_str().unwrap().as_bytes(),
            b"article\n  r1 link \"quoted\" \xe2\x80\x94 caf\xc3\xa9\t\xe7\xb5\x82"
        );
        assert_eq!(
            result["content"][2]["text"].as_str().unwrap().as_bytes(),
            b"Image reference-1 was not delivered: inline_bytes_missing"
        );
        assert!(result.get("isError").is_none());
    }

    #[test]
    fn non_string_state_and_missing_image_bytes_match_legacy_projection() {
        let result = decoded(
            json!({"state_text":false, "image":{"image_id":"reference-1", "mime":"video/mp4", "width":1,"height":1}}),
        );
        assert_eq!(
            result["content"][1]["text"],
            "Image reference-1 was not delivered: inline_bytes_missing"
        );
        assert!(result["content"][0]["text"]
            .as_str()
            .unwrap()
            .ends_with(r#", "state_text":false}"#.replace(", ", ",").as_str()));
    }
}
