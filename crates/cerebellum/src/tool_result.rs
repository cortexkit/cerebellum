//! Model-facing projection belongs to the provider; structured replies retain
//! the identifiers and outcomes programs need without repeating image bytes in text.

use crate::ModuleError;
use cortexkit_role_tool_provider::result::{self, ContentPart, ImageContent, ToolResult};
use serde_json::{json, Map, Value};

mod plain;

tokio::task_local! {
    pub(crate) static RESULT_BIND: Option<(String, cerebellum_core::identity::AcceptedBindFacts)>;
}

fn notice(id: Option<&str>, reason: &str) -> String {
    format!(
        "Image {} was not delivered: {reason}",
        id.unwrap_or("unknown id")
    )
}

fn image_projection(value: &Value) -> (Option<ImageContent>, Option<String>) {
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
    (image, reason.map(|reason| notice(id.as_deref(), reason)))
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

fn login_notice(object: &Map<String, Value>) -> Option<String> {
    let origin = object.get("origin")?.as_str()?;
    Some(match object.get("outcome")?.as_str()? {
        "login_observed" => format!("Sign-in on {origin} was observed. Continue with snapshot."),
        "expired" | "handoff_expired" => format!("The sign-in window on {origin} expired before a login was seen. Call present again if still needed."),
        "handoff_interrupted" => format!("The sign-in handoff on {origin} was interrupted by a restart. Call present again."),
        "captured" => format!("Sign-in on {origin} was captured in the vault. Continue with the authenticated request."),
        "session_invalid" => format!("The captured sign-in on {origin} could not be verified. Call capture_login again."),
        "closed_by_caller" => format!("The sign-in handoff on {origin} was closed by the caller."),
        _ => return None,
    })
}

fn project(reply: Value) -> ToolResult {
    let Some(object) = reply.as_object() else {
        // Every provider reply is an object; anything else has no fields to
        // describe, so the model is told that rather than shown the value.
        let text = match &reply {
            Value::String(text) if !text.trim().is_empty() => text.clone(),
            _ => "The tool returned a reply this module cannot describe.".to_string(),
        };
        return ToolResult::new(vec![ContentPart::text(text)]);
    };
    // The text parts are the whole model view: a reader shows only them, and
    // keeps structuredContent for programs. They are written as sentences and
    // short lines, never as JSON (see `plain`).
    let mut content = Vec::new();
    if let Some(body) = plain::body(object).filter(|body| !body.trim().is_empty()) {
        content.push(ContentPart::text(body));
    }
    let projected_image = object.get("image").map(image_projection);
    let facts = plain::facts(object, login_notice(object));
    if !facts.is_empty() {
        content.push(ContentPart::text(facts.join("\n")));
    }
    let image = projected_image.and_then(|(image, note)| {
        if let Some(note) = note {
            content.push(ContentPart::text(note));
        }
        image
    });
    let code = object.get("outcome").and_then(Value::as_str);
    // A reader that finds no text shows structuredContent as JSON instead, so
    // even a plain success with nothing else to say carries one line.
    if !content.iter().any(|part| match part {
        ContentPart::Text { text } => !text.trim().is_empty(),
        _ => false,
    }) {
        content.push(ContentPart::text(match code {
            Some(code) if !is_success(code) => plain::sentence(&code.replace('_', " ")),
            _ => "Done.".to_string(),
        }));
    }
    let mut result = ToolResult::new(content).with_structured_content(object.clone());
    if let Some(code) = code.filter(|code| !is_success(code)) {
        result = result.with_error(code);
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

/// Why a content/v1 result would not give the model a plain view, or an
/// empty list when it would. Two rules, both from how readers render a reply:
///
/// * at least one text part says something, because a reader that finds no
///   text shows the structured copy to the model as JSON instead;
/// * no text part contains a JSON object or array with two or more members.
///   Every `{` and `[` is tried as the start of a JSON value, so a fragment
///   is found wherever it sits in a line. One-member values are let through
///   because ordinary text such as `[value withheld]` or `[2]` is not JSON
///   worth refusing, and the replies this guards never print one.
#[cfg(test)]
pub(crate) fn model_view_problems(result: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    let parts = result["content"].as_array().cloned().unwrap_or_default();
    let texts: Vec<&str> = parts
        .iter()
        .filter(|part| part["type"] == "text")
        .filter_map(|part| part["text"].as_str())
        .collect();
    if !texts.iter().any(|text| !text.trim().is_empty()) {
        problems.push("no text part says anything".to_string());
    }
    for text in texts {
        for (start, _) in text.match_indices(['{', '[']) {
            let mut values =
                serde_json::Deserializer::from_str(&text[start..]).into_iter::<Value>();
            let members = match values.next() {
                Some(Ok(Value::Object(object))) => object.len(),
                Some(Ok(Value::Array(array))) => array.len(),
                _ => continue,
            };
            if members >= 2 {
                problems.push(format!("JSON in a text part: {text:?}"));
                break;
            }
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decoded(reply: Value) -> Value {
        serde_json::from_slice(&encode(reply).unwrap()).unwrap()
    }

    fn texts(result: &Value) -> Vec<String> {
        result["content"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|part| part["type"] == "text")
            .map(|part| part["text"].as_str().unwrap().to_string())
            .collect()
    }

    // The metadata line these tests once pinned was the reply's other fields
    // printed as JSON. The operator ruled that no JSON reaches the model, so
    // each now pins the plain words that replace it, and the same reply
    // still travels whole as structuredContent.
    #[test]
    fn snapshot_state_text_is_verbatim_first_part() {
        let reply = json!({"outcome":"ok", "state_text":"article\n  r1 link \"quoted\" — café", "snapshot_id":"snap-1"});
        let result = decoded(reply.clone());
        assert_eq!(
            result["content"][0],
            json!({"type":"text", "text":"article\n  r1 link \"quoted\" — café"})
        );
        assert_eq!(result["content"][1]["text"], "snapshot_id: snap-1");
        assert_eq!(result["structuredContent"], reply);
        assert!(result.get("isError").is_none());
    }

    #[test]
    fn a_snapshot_whose_header_names_its_id_does_not_repeat_it() {
        let reply = json!({"outcome":"ok", "state_text":"news.example · snapshot snap-1\ne1 button Go", "snapshot_id":"snap-1", "document_epoch":1, "context":{"profile_name":"default"}});
        assert_eq!(
            texts(&decoded(reply)),
            ["news.example · snapshot snap-1\ne1 button Go"]
        );
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
            json!({"type":"text", "text":"Image image-1, 12×8 px."})
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
            texts(&result),
            ["Consent unavailable.\nAn agent run cannot ask a person.\nReason: agent run."]
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
        assert_eq!(
            result["structuredContent"]["image"]["data_b64"], "AB==",
            "programs still receive the reply as it was"
        );
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
    fn non_string_state_and_missing_image_bytes_are_described_in_words() {
        let result = decoded(
            json!({"state_text":false, "image":{"image_id":"reference-1", "mime":"video/mp4", "width":1,"height":1}}),
        );
        assert_eq!(
            texts(&result),
            [
                "Image reference-1, 1×1 px.",
                "Image reference-1 was not delivered: inline_bytes_missing"
            ]
        );
    }

    #[test]
    fn a_plain_success_says_done_rather_than_nothing() {
        let result = decoded(json!({"outcome":"completed", "unreadable_subtrees":0}));
        assert_eq!(texts(&result), ["Done."]);
        let result = decoded(
            json!({"outcome":"completed", "focused_element_id":"mp3", "unreadable_subtrees":3, "state_text":"+ e1 button Go\n"}),
        );
        assert_eq!(
            texts(&result),
            [
                "+ e1 button Go\n",
                "Focused: mp3.\n3 parts couldn't be read."
            ]
        );
    }

    #[test]
    fn list_apps_reads_as_a_list_not_an_array() {
        let mut apps = vec![
            json!({"name":"Finder","bundle_identity":"com.apple.finder","running":true,"pid":101,"frontmost":true}),
            json!({"name":"Mail","bundle_identity":"com.apple.mail","running":true,"pid":102,"frontmost":false}),
        ];
        apps.extend(["Calculator", "Chess"].map(|name| {
            json!({"name":name,"bundle_identity":format!("com.apple.{name}"),"running":false,"frontmost":false})
        }));
        let result = decoded(
            json!({"outcome":"completed", "state_text":"legacy text", "apps":apps, "truncated":false, "installed_list":"complete"}),
        );
        assert_eq!(
            texts(&result),
            ["Running apps:\nFinder · com.apple.finder · pid 101 · frontmost\nMail · com.apple.mail · pid 102\nInstalled, not running (2): Calculator, Chess\n"]
        );
        let many: Vec<Value> = (0..400)
            .map(|index| json!({"name":format!("Application {index}"),"bundle_identity":format!("com.example.app{index}"),"running":false,"frontmost":false}))
            .collect();
        let result = decoded(
            json!({"outcome":"completed", "apps":many, "truncated":false, "installed_list":"partial"}),
        );
        assert_eq!(
            texts(&result),
            [
                "No running app is listed.\n400 installed apps that are not running are not shown; call list_apps with text_filter to find one by name or bundle id.\n",
                "Not every installed app could be read in time, so the installed list is partial."
            ]
        );
    }

    #[test]
    fn name_refusals_list_candidates_by_name() {
        let result = decoded(
            json!({"outcome":"no_running_app_named", "target":"Magic", "remedy":"list_apps shows the running applications"}),
        );
        assert_eq!(
            texts(&result),
            ["No running app is named Magic.\nlist_apps shows the running applications."]
        );
        let result = decoded(
            json!({"outcome":"ambiguous_app", "target":"Magic", "candidates":[
            {"name":"Magic Context Dashboard","bundle_identity":"com.example.dashboard","pid":1},
            {"name":"Magic Mouse Utility","bundle_identity":"com.example.mouse","pid":2}],
            "remedy":"retry with the full name"}),
        );
        assert_eq!(
            texts(&result),
            ["Magic matches more than one app: Magic Context Dashboard (com.example.dashboard), Magic Mouse Utility (com.example.mouse).\nRetry with the full name."]
        );
    }

    #[test]
    fn consent_pending_names_the_question_and_what_to_do() {
        let result = decoded(
            json!({"outcome":"consent_pending", "ask_id":"ask-7", "remedy":"the person has been asked; the answer arrives as a notice", "detail":{"grant":"app","grant_label":"Use TextEdit"}}),
        );
        assert_eq!(
            texts(&result),
            ["Waiting for the person to answer a consent question (ask_id ask-7).\nThe person has been asked; the answer arrives as a notice.\nGrant asked for: Use TextEdit."]
        );
    }

    #[test]
    fn the_guard_finds_json_wherever_it_sits_and_passes_plain_text() {
        let plain = decoded(
            json!({"outcome":"completed", "state_text":"e1 text field, Value: [value withheld]\ne2 menu  [3 children; closed]"}),
        );
        assert_eq!(model_view_problems(&plain), Vec::<String>::new());
        for text in [
            r#"{"outcome":"ok","snapshot_id":"x"}"#,
            r#"Done. trailing ["a", "b"] list"#,
            r#"prefix {"a": {"b": 1}, "c": 2} suffix"#,
        ] {
            let result = json!({"content":[{"type":"text","text":text}]});
            assert_eq!(model_view_problems(&result).len(), 1, "{text}");
        }
        assert_eq!(
            model_view_problems(&json!({"content":[{"type":"text","text":"  "}]})),
            ["no text part says anything"]
        );
    }
}
