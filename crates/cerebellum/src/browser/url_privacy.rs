//! Origin-only projection for browser details before durable journal writes.

use cerebellum_core::journal::refusal_ring::reduce_url_to_origin;

/// Durable details may contain nested replies and URL-bearing failure text.
/// Keep their shape, but never retain a URL's credentials, path, query or fragment.
pub(super) fn urls_to_origins(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => {
            let mut remaining = text.as_str();
            let mut redacted = String::new();
            while let Some(separator) = remaining.find("://") {
                let start = remaining[..separator]
                    .rfind(|ch: char| !ch.is_ascii_alphanumeric() && !matches!(ch, '+' | '-' | '.'))
                    .map_or(0, |index| {
                        index + remaining[index..].chars().next().unwrap().len_utf8()
                    });
                let end = remaining[separator + 3..]
                    .find(|ch: char| ch.is_whitespace() || matches!(ch, '\'' | '"' | '<' | '>'))
                    .map_or(remaining.len(), |index| separator + 3 + index);
                redacted.push_str(&remaining[..start]);
                redacted.push_str(&reduce_url_to_origin(&remaining[start..end]));
                remaining = &remaining[end..];
            }
            if !redacted.is_empty() {
                redacted.push_str(remaining);
                *text = redacted;
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(urls_to_origins),
        serde_json::Value::Object(fields) => {
            for (key, value) in fields {
                if (key == "url" || key.starts_with("url_") || key.ends_with("_url"))
                    && value.is_string()
                {
                    *value =
                        serde_json::Value::String(reduce_url_to_origin(value.as_str().unwrap()));
                } else {
                    urls_to_origins(value);
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod url_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn durable_urls_are_origin_only_in_nested_replies_and_failure_text() {
        let mut detail = json!({
            "url_final":"https://user:password@EXAMPLE.com:8443/path?code=secret#secret",
            "read_page":{"url":"https://example.com/private"},
            "detail":{"error_text":"could not load https://example.com/reset?token=secret before deadline"},
            "origins":["https://example.com:443", "http://[::1]:8080/private"],
            "outcome":"ok", "loaded":true
        });
        urls_to_origins(&mut detail);
        assert_eq!(
            detail,
            json!({
                "url_final":"https://example.com:8443",
                "read_page":{"url":"https://example.com"},
                "detail":{"error_text":"could not load https://example.com before deadline"},
                "origins":["https://example.com", "http://[::1]:8080"],
                "outcome":"ok", "loaded":true
            })
        );
    }
}
