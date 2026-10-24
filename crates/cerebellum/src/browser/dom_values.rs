//! Value masking for Chrome-serialized HTML, without reserializing unrelated bytes.

use std::borrow::Cow;
use std::ops::Range;

struct Attribute<'a> {
    name: &'a str,
    value: &'a str,
    replacement: Range<usize>,
    quoted: bool,
    has_value: bool,
}

struct Tag<'a> {
    name: &'a str,
    end: usize,
    closing: bool,
    attributes: Vec<Attribute<'a>>,
}

fn space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0c)
}

/// Tokenize a start/end tag, respecting quoted attribute values. Offsets refer
/// to the original markup so attributes not being masked remain byte-identical.
fn tag_at(markup: &str, start: usize) -> Option<Tag<'_>> {
    let bytes = markup.as_bytes();
    let mut at = start + 1;
    let closing = bytes.get(at) == Some(&b'/');
    at += usize::from(closing);
    if !bytes.get(at)?.is_ascii_alphabetic() {
        return None;
    }
    let name_start = at;
    while at < bytes.len() && !space(bytes[at]) && !matches!(bytes[at], b'/' | b'>') {
        at += 1;
    }
    let name = &markup[name_start..at];
    let mut attributes = Vec::new();
    while at < bytes.len() {
        if bytes[at] == b'>' {
            return Some(Tag {
                name,
                end: at + 1,
                closing,
                attributes,
            });
        }
        if space(bytes[at]) || bytes[at] == b'/' {
            at += 1;
            continue;
        }
        let name_start = at;
        while at < bytes.len() && !space(bytes[at]) && !matches!(bytes[at], b'=' | b'/' | b'>') {
            at += 1;
        }
        // An unexpected '=' still advances the tokenizer on malformed markup.
        if at == name_start {
            at += 1;
            continue;
        }
        let name_end = at;
        while at < bytes.len() && space(bytes[at]) {
            at += 1;
        }
        let has_value = bytes.get(at) == Some(&b'=');
        let mut quoted = false;
        let mut replacement = name_end..name_end;
        if has_value {
            at += 1;
            while at < bytes.len() && space(bytes[at]) {
                at += 1;
            }
            quoted = matches!(bytes.get(at), Some(b'\'' | b'"'));
            if quoted {
                let quote = bytes[at];
                at += 1;
                let value_start = at;
                while at < bytes.len() && bytes[at] != quote {
                    at += 1;
                }
                replacement = value_start..at;
                at += usize::from(at < bytes.len());
            } else {
                let value_start = at;
                while at < bytes.len() && !space(bytes[at]) && bytes[at] != b'>' {
                    at += 1;
                }
                replacement = value_start..at;
            }
        }
        attributes.push(Attribute {
            name: &markup[name_start..name_end],
            value: &markup[replacement.clone()],
            replacement,
            quoted,
            has_value,
        });
    }
    None
}

fn fixed_input_value(kind: &str) -> bool {
    ["button", "submit", "reset", "image", "checkbox", "radio"]
        .iter()
        .any(|allowed| kind.eq_ignore_ascii_case(allowed))
}

/// Raw text and RCDATA recognize their own end tag, not tags in their contents.
fn raw_end(markup: &str, mut at: usize, name: &str) -> usize {
    let bytes = markup.as_bytes();
    while let Some(next) = markup[at..].find('<') {
        at += next;
        let end = at + 2 + name.len();
        if bytes.get(at + 1) == Some(&b'/')
            && bytes
                .get(at + 2..end)
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(name.as_bytes()))
            && bytes
                .get(end)
                .is_some_and(|byte| space(*byte) || matches!(byte, b'/' | b'>'))
        {
            return at;
        }
        at += 1;
    }
    markup.len()
}

/// Script's legacy HTML-comment escapes can double-escape an inner `script`
/// tag. Its first closing tag then exits that escape, not the real element.
fn script_end(markup: &str, mut at: usize) -> usize {
    let bytes = markup.as_bytes();
    let mut escaped = false;
    let mut double_escaped = false;
    while at < bytes.len() {
        let rest = &bytes[at..];
        if !escaped && rest.starts_with(b"<!--") {
            escaped = true;
            at += 4;
            continue;
        }
        if escaped && rest.starts_with(b"-->") {
            escaped = false;
            double_escaped = false;
            at += 3;
            continue;
        }
        let closing = rest.starts_with(b"</");
        let prefix = if closing { 2 } else { 1 };
        let script_tag = rest.first() == Some(&b'<')
            && rest
                .get(prefix..prefix + 6)
                .is_some_and(|name| name.eq_ignore_ascii_case(b"script"))
            && rest
                .get(prefix + 6)
                .is_some_and(|byte| space(*byte) || matches!(byte, b'/' | b'>'));
        if script_tag {
            if closing {
                if !double_escaped {
                    return at;
                }
                double_escaped = false;
            } else if escaped {
                double_escaped = true;
            }
            at += prefix + 6;
        } else {
            at += 1;
        }
    }
    markup.len()
}

fn comment_end(markup: &str, start: usize) -> usize {
    let body = &markup[start + 4..];
    if body.starts_with('>') {
        return start + 5;
    }
    if body.starts_with("->") {
        return start + 6;
    }
    body.find("-->")
        .map(|at| at + 3)
        .into_iter()
        .chain(body.find("--!>").map(|at| at + 4))
        .min()
        .map_or(markup.len(), |end| start + 4 + end)
}

fn doctype_end(markup: &str, start: usize) -> usize {
    let mut quote = None;
    for (offset, byte) in markup.as_bytes()[start..].iter().copied().enumerate() {
        if quote == Some(byte) {
            quote = None;
        } else if quote.is_none() {
            if matches!(byte, b'\'' | b'"') {
                quote = Some(byte);
            } else if byte == b'>' {
                return start + offset + 1;
            }
        }
    }
    markup.len()
}

/// Mask only field tokens. Comments, raw text and ordinary element text are
/// copied unchanged; Chrome has already escaped entities in attribute values.
/// `noscript` is treated as markup because either browser can disable scripting,
/// allowing real form controls inside that container.
pub(super) fn mask_field_values(markup: &str) -> Cow<'_, str> {
    let mut changes = Vec::new();
    let mut at = 0;
    while let Some(next) = markup[at..].find('<') {
        at += next;
        if markup[at..].starts_with("<!--") {
            at = comment_end(markup, at);
            continue;
        }
        if markup.as_bytes()[at..]
            .get(..9)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"<!doctype"))
        {
            at = doctype_end(markup, at);
            continue;
        }
        if markup[at..].starts_with("<![CDATA[") {
            at = markup[at + 9..]
                .find("]]>")
                .map_or(markup.len(), |end| at + 9 + end + 3);
            continue;
        }
        if markup[at..].starts_with("<!") || markup[at..].starts_with("<?") {
            at = markup[at..]
                .find('>')
                .map_or(markup.len(), |end| at + end + 1);
            continue;
        }
        let Some(tag) = tag_at(markup, at) else {
            at += 1;
            continue;
        };
        at = tag.end;
        if tag.closing {
            continue;
        }
        if tag.name.eq_ignore_ascii_case("input") {
            let kind = tag
                .attributes
                .iter()
                .find(|attr| attr.name.eq_ignore_ascii_case("type"));
            if !kind.is_some_and(|kind| fixed_input_value(kind.value)) {
                for attr in tag
                    .attributes
                    .iter()
                    .filter(|attr| attr.name.eq_ignore_ascii_case("value"))
                {
                    let masked = if attr.quoted {
                        "(hidden)"
                    } else if attr.has_value {
                        "\"(hidden)\""
                    } else {
                        "=\"(hidden)\""
                    };
                    changes.push((attr.replacement.clone(), masked));
                }
            }
        } else if tag.name.eq_ignore_ascii_case("textarea") {
            let end = raw_end(markup, at, tag.name);
            changes.push((at..end, "(hidden)"));
            at = end;
        } else if tag.name.eq_ignore_ascii_case("script") {
            at = script_end(markup, at);
        } else if ["style", "title", "xmp", "iframe", "noembed", "noframes"]
            .iter()
            .any(|name| tag.name.eq_ignore_ascii_case(name))
        {
            at = raw_end(markup, at, tag.name);
        } else if tag.name.eq_ignore_ascii_case("plaintext") {
            break;
        }
    }
    if changes.is_empty() {
        return Cow::Borrowed(markup);
    }
    let mut output = String::with_capacity(markup.len());
    let mut copied = 0;
    for (range, masked) in changes {
        output.push_str(&markup[copied..range.start]);
        output.push_str(masked);
        copied = range.end;
    }
    output.push_str(&markup[copied..]);
    Cow::Owned(output)
}

#[cfg(test)]
mod tests {
    use super::mask_field_values;

    #[test]
    fn attributes_are_tokenized_in_any_order_and_case() {
        assert_eq!(
            mask_field_values(
                r#"<INPUT VALUE="s&amp;&quot;&gt;é" data-note=">" TYPE="PASSWORD"/>"#
            ),
            r#"<INPUT VALUE="(hidden)" data-note=">" TYPE="PASSWORD"/>"#,
        );
        assert_eq!(
            mask_field_values(r#"<input value="Go &amp; send" TYPE="SuBmIt" />"#),
            r#"<input value="Go &amp; send" TYPE="SuBmIt" />"#,
        );
        assert_eq!(
            mask_field_values("<input value='secret' type=text>"),
            "<input value='(hidden)' type=text>"
        );
        assert_eq!(
            mask_field_values("<input value=secret />"),
            "<input value=\"(hidden)\" />"
        );
        assert_eq!(
            mask_field_values("<input value>"),
            "<input value=\"(hidden)\">"
        );
        assert_eq!(
            mask_field_values(r#"<input value="secret" type="unknown">"#),
            r#"<input value="(hidden)" type="unknown">"#
        );
        assert_eq!(
            mask_field_values("<input title=\"value='not a field'\">"),
            "<input title=\"value='not a field'\">"
        );
    }

    #[test]
    fn comments_and_raw_text_do_not_contain_field_tokens() {
        for tag in [
            "script", "style", "title", "xmp", "iframe", "noembed", "noframes",
        ] {
            let markup =
                format!(r#"<{tag}><input value="not-a-field"></{tag}><input value="secret">"#);
            let expected =
                format!(r#"<{tag}><input value="not-a-field"></{tag}><input value="(hidden)">"#);
            assert_eq!(mask_field_values(&markup), expected);
        }
        for comment in [
            r#"<!-- <input value="not-a-field"> -->"#,
            r#"<!-- <input value="not-a-field"> --!>"#,
            "<!-->",
            "<!--->",
        ] {
            let markup = format!(r#"{comment}<input value="secret">"#);
            assert_eq!(
                mask_field_values(&markup),
                format!(r#"{comment}<input value="(hidden)">"#)
            );
        }
        let text = r#"<plaintext><input value="not-a-field">"#;
        assert_eq!(mask_field_values(text), text);
    }

    #[test]
    fn textarea_content_is_masked_as_one_rcdata_token() {
        assert_eq!(
            mask_field_values(
                r#"<TEXTAREA rows="2">&lt;input value=&quot;secret&quot;&gt;é</TEXTAREA><input value="secret">"#
            ),
            r#"<TEXTAREA rows="2">(hidden)</TEXTAREA><input value="(hidden)">"#,
        );
        assert_eq!(
            mask_field_values("<textarea>secret</textareax>still secret</textarea>"),
            "<textarea>(hidden)</textarea>"
        );
        assert_eq!(
            mask_field_values("<textarea/>secret</textarea>"),
            "<textarea/>(hidden)</textarea>"
        );
        assert_eq!(
            mask_field_values("<textarea></textarea>"),
            "<textarea>(hidden)</textarea>"
        );
    }

    #[test]
    fn double_escaped_script_content_is_not_a_field() {
        let markup = concat!(
            r#"<script><!--<script><input value="not-a-field"></script>"#,
            r#"<input value="still-not-a-field">--></SCRIPT>"#,
            r#"<input value="secret">"#,
        );
        let expected = concat!(
            r#"<script><!--<script><input value="not-a-field"></script>"#,
            r#"<input value="still-not-a-field">--></SCRIPT>"#,
            r#"<input value="(hidden)">"#,
        );
        assert_eq!(mask_field_values(markup), expected);
    }

    #[test]
    fn document_declarations_are_not_field_start_tags() {
        let markup = concat!(
            "<!DOCTYPE html SYSTEM \"<input value='not-a-field'>\">",
            r#"<svg><![CDATA[> <input value="not-a-field">]]></svg>"#,
            r#"<input value="secret">"#,
        );
        let expected = concat!(
            "<!DOCTYPE html SYSTEM \"<input value='not-a-field'>\">",
            r#"<svg><![CDATA[> <input value="not-a-field">]]></svg>"#,
            r#"<input value="(hidden)">"#,
        );
        assert_eq!(mask_field_values(markup), expected);
    }

    #[test]
    fn noscript_can_contain_real_controls_when_scripting_is_disabled() {
        assert_eq!(
            mask_field_values(r#"<noscript><input value="secret"></noscript>"#),
            r#"<noscript><input value="(hidden)"></noscript>"#,
        );
    }
}
