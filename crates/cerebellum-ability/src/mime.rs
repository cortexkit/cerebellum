//! Bounded, host-neutral MIME decoding. Attachment ancestry is never body text.

use encoding_rs::Encoding;
use mailparse::{DispositionType, MailAddr, MailHeaderMap};

use crate::{caps, items::Address, items::BodyState};

pub const MAX_MESSAGE_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_MIME_DEPTH: usize = 32;
pub const MAX_MIME_PARTS: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    InputTooLarge,
    NestingTooDeep,
    TooManyParts,
    Malformed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Header {
    pub name: String,
    pub value: String,
}

/// Parts are in document order; `parent` indexes an earlier part in this list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Part {
    pub parent: Option<usize>,
    pub mime_type: String,
    pub excluded: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    pub headers: Vec<Header>,
    pub parts: Vec<Part>,
    pub from: Option<Address>,
    pub to: Vec<Address>,
    pub cc: Vec<Address>,
    pub subject: Option<String>,
    pub body: Option<String>,
    pub body_state: BodyState,
    pub truncated: Vec<String>,
}

/// Parse a complete RFC 5322 message, not an emlx length line or metadata plist.
/// Structural failures refuse the message. A bad first eligible plain-text body
/// is `undecodable`, rather than a reason to substitute a later MIME part.
pub fn parse(input: &[u8]) -> Result<Message, ParseError> {
    if input.len() > MAX_MESSAGE_BYTES {
        return Err(ParseError::InputTooLarge);
    }
    let mut result = Message {
        headers: Vec::new(),
        parts: Vec::new(),
        from: None,
        to: Vec::new(),
        cc: Vec::new(),
        subject: None,
        body: None,
        body_state: BodyState::NoPlainText,
        truncated: Vec::new(),
    };
    let mut pending = vec![(input, None, false, 0, false)];
    let mut selected = false;
    while let Some((raw, parent, inherited_exclusion, depth, digest_child)) = pending.pop() {
        if depth > MAX_MIME_DEPTH {
            return Err(ParseError::NestingTooDeep);
        }
        if result.parts.len() == MAX_MIME_PARTS {
            return Err(ParseError::TooManyParts);
        }
        // Only header parsing is used on containers. mailparse's recursive
        // multipart parser never sees attacker-controlled nesting.
        let (headers, body_start) =
            mailparse::parse_headers(raw).map_err(|_| ParseError::Malformed)?;
        let content_type = headers.get_first_value("Content-Type");
        let ctype =
            mailparse::parse_content_type(content_type.as_deref().unwrap_or(if digest_child {
                "message/rfc822"
            } else {
                "text/plain"
            }));
        let disposition = mailparse::parse_content_disposition(
            &headers
                .get_first_value("Content-Disposition")
                .unwrap_or_default(),
        );
        let named = |params: &std::collections::BTreeMap<String, String>| {
            params.keys().any(|key| {
                let key = key.split('*').next().unwrap_or(key);
                key.eq_ignore_ascii_case("filename") || key.eq_ignore_ascii_case("name")
            })
        };
        let excluded = inherited_exclusion
            || disposition.disposition == DispositionType::Attachment
            || named(&disposition.params)
            || named(&ctype.params)
            || ctype.mimetype.eq_ignore_ascii_case("message/rfc822");
        let index = result.parts.len();
        result.parts.push(Part {
            parent,
            mime_type: ctype.mimetype.clone(),
            excluded,
        });
        if parent.is_none() {
            result.from = addresses(&headers, "From").into_iter().next();
            result.to = addresses(&headers, "To");
            result.cc = addresses(&headers, "Cc");
            result.subject = headers.get_first_value("Subject");
            result.headers = headers
                .iter()
                .map(|header| Header {
                    name: header.get_key(),
                    value: header.get_value(),
                })
                .collect();
        }
        if ctype.mimetype.starts_with("multipart/") {
            let boundary = ctype.params.get("boundary").ok_or(ParseError::Malformed)?;
            let children = split_multipart(&raw[body_start..], boundary)?;
            if children.len() + pending.len() + result.parts.len() > MAX_MIME_PARTS {
                return Err(ParseError::TooManyParts);
            }
            for child in children.into_iter().rev() {
                pending.push((
                    child,
                    Some(index),
                    excluded,
                    depth + 1,
                    ctype.mimetype == "multipart/digest",
                ));
            }
        } else if !excluded && !selected && ctype.mimetype == "text/plain" {
            selected = true;
            match decode_text(raw, &ctype.charset, &headers) {
                Some(text) => {
                    result.body = Some(text);
                    result.body_state = BodyState::Ok;
                }
                None => result.body_state = BodyState::Undecodable,
            }
        }
    }
    normalize(&mut result);
    Ok(result)
}

fn addresses(headers: &[mailparse::MailHeader<'_>], field: &str) -> Vec<Address> {
    let mut result = Vec::new();
    for header in headers.get_all_headers(field) {
        let Ok(addresses) = mailparse::addrparse_header(header) else {
            continue;
        };
        for address in addresses.iter() {
            let singles = match address {
                MailAddr::Single(single) => std::slice::from_ref(single),
                MailAddr::Group(group) => group.addrs.as_slice(),
            };
            result.extend(singles.iter().map(|single| Address {
                name: single.display_name.clone(),
                address: single.addr.clone(),
            }));
        }
    }
    result
}

fn decode_text(raw: &[u8], charset: &str, headers: &[mailparse::MailHeader<'_>]) -> Option<String> {
    let transfer = headers
        .get_first_value("Content-Transfer-Encoding")
        .unwrap_or_else(|| "7bit".into());
    if !["7bit", "8bit", "binary", "base64", "quoted-printable"]
        .contains(&transfer.trim().to_ascii_lowercase().as_str())
    {
        return None;
    }
    // This is a leaf with an already-parsed non-multipart Content-Type.
    let bytes = mailparse::parse_mail(raw).ok()?.get_body_raw().ok()?;
    if charset.eq_ignore_ascii_case("us-ascii") || charset.eq_ignore_ascii_case("ascii") {
        return bytes
            .is_ascii()
            .then(|| String::from_utf8(bytes).ok())
            .flatten();
    }
    Encoding::for_label(charset.as_bytes())?
        .decode_without_bom_handling_and_without_replacement(&bytes)
        .map(|text| text.into_owned())
}

/// Split without recursion, accepting only delimiter lines (never substrings
/// inside a payload). Preamble and epilogue are not MIME parts.
fn split_multipart<'a>(body: &'a [u8], boundary: &str) -> Result<Vec<&'a [u8]>, ParseError> {
    if boundary.is_empty() || boundary.len() > 70 || boundary.bytes().any(|b| b < 32 || b == 127) {
        return Err(ParseError::Malformed);
    }
    let delimiter = format!("--{boundary}");
    let mut parts = Vec::new();
    let mut start = None;
    let mut offset = 0;
    for line in body.split_inclusive(|b| *b == b'\n') {
        let end = offset + line.len();
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let line = line.trim_ascii_end();
        if let Some(suffix) = line.strip_prefix(delimiter.as_bytes()) {
            if suffix.is_empty() || suffix == b"--" {
                if let Some(begin) = start {
                    let mut part = &body[begin..offset];
                    part = part.strip_suffix(b"\n").unwrap_or(part);
                    part = part.strip_suffix(b"\r").unwrap_or(part);
                    parts.push(part);
                    if parts.len() > MAX_MIME_PARTS {
                        return Err(ParseError::TooManyParts);
                    }
                }
                if suffix == b"--" {
                    return Ok(parts);
                }
                start = Some(end);
            }
        }
        offset = end;
    }
    Err(ParseError::Malformed)
}

fn normalize(message: &mut Message) {
    for (field, cut) in [
        ("from", caps::optional_address(&mut message.from)),
        ("to", caps::addresses(&mut message.to)),
        ("cc", caps::addresses(&mut message.cc)),
        ("subject", caps::free_text(&mut message.subject)),
        (
            "body",
            caps::optional_string(&mut message.body, caps::BODY_BYTES),
        ),
    ] {
        if cut {
            message.truncated.push(field.into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn multipart(parts: &[&str]) -> String {
        let mut raw =
            "Content-Type: multipart/mixed; boundary=outer\r\n\r\nPreamble\r\n".to_owned();
        for part in parts {
            raw.push_str(&format!("--outer\r\n{part}\r\n"));
        }
        raw.push_str("--outer--\r\nEpilogue");
        raw
    }

    #[test]
    fn first_plain_part_in_document_order_decodes_transfer_and_charset() {
        let nested = concat!(
            "Content-Type: multipart/alternative; boundary=inner\r\n\r\n",
            "--inner\r\nContent-Type: text/html\r\n\r\n<p>not plain</p>\r\n",
            "--inner\r\nContent-Type: text/plain; charset=iso-8859-1\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n\r\ncaf=E9\r\n--inner--"
        );
        let raw = multipart(&[nested, "Content-Type: text/plain\r\n\r\nsecond"]);
        let decoded = parse(raw.as_bytes()).unwrap();
        assert_eq!(decoded.body.as_deref(), Some("café"));
        assert_eq!(decoded.body_state, BodyState::Ok);
        let base64 = parse(b"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n5pel5pys6Kqe").unwrap();
        assert_eq!(base64.body.as_deref(), Some("日本語"));
        for transfer in ["7bit", "8bit", "binary"] {
            let raw = format!("Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: {transfer}\n\nnaïve");
            assert_eq!(
                parse(raw.as_bytes()).unwrap().body.as_deref(),
                Some("naïve")
            );
        }
    }

    #[test]
    fn html_and_every_attachment_ancestor_never_supply_body_text() {
        let html = "Content-Type: text/html\r\n\r\n<p>HTML</p>";
        let attachments = [
            "Content-Type: text/plain\r\nContent-Disposition: ATTACHMENT\r\n\r\nSECRET",
            "Content-Type: text/plain; name=\"note.txt\"\r\n\r\nSECRET",
            "Content-Type: text/plain\r\nContent-Disposition: inline; filename=note.txt\r\n\r\nSECRET",
            "Content-Type: text/plain\r\nContent-Disposition: inline; filename*=utf-8''note.txt\r\n\r\nSECRET",
            "Content-Type: multipart/mixed; boundary=a\r\nContent-Disposition: attachment\r\n\r\n--a\r\nContent-Type: text/plain\r\n\r\nSECRET\r\n--a--",
            "Content-Type: multipart/mixed; boundary=a; name=attached\r\n\r\n--a\r\nContent-Type: text/plain\r\n\r\nSECRET\r\n--a--",
            "Content-Type: message/rfc822\r\nContent-Disposition: attachment\r\n\r\nSubject: Attached\r\nContent-Type: text/plain\r\n\r\nSECRET",
            "Content-Type: message/rfc822\r\n\r\nContent-Type: text/plain\r\n\r\nSECRET",
            "Content-Type: multipart/digest; boundary=d\r\n\r\n--d\r\n\r\nSubject: Attached\r\n\r\nSECRET\r\n--d--",
        ];
        assert_eq!(
            parse(html.as_bytes()).unwrap().body_state,
            BodyState::NoPlainText
        );
        for attachment in attachments {
            let decoded = parse(multipart(&[html, attachment]).as_bytes()).unwrap();
            assert_eq!(decoded.body_state, BodyState::NoPlainText, "{attachment}");
            assert_eq!(decoded.body, None, "{attachment}");
            let plain = "Content-Type: text/plain\r\n\r\nvisible";
            assert_eq!(
                parse(multipart(&[attachment, plain]).as_bytes())
                    .unwrap()
                    .body
                    .as_deref(),
                Some("visible")
            );
        }
    }

    #[test]
    fn addresses_decode_names_groups_and_absent_headers() {
        let raw = concat!(
            "From: =?UTF-8?B?w4FsaWNl?= <alice@example.test>\r\n",
            "To: bob@example.test, \"Doe, Jane\" <jane@example.test>\r\n",
            "Cc: Friends: Carol <carol@example.test>, dan@example.test;\r\n",
            "To: eve@example.test\r\n\r\nBody"
        );
        let parsed = parse(raw.as_bytes()).unwrap();
        assert_eq!(
            parsed.from,
            Some(Address {
                name: Some("Álice".into()),
                address: "alice@example.test".into()
            })
        );
        assert_eq!(
            parsed.to,
            vec![
                Address {
                    name: None,
                    address: "bob@example.test".into()
                },
                Address {
                    name: Some("Doe, Jane".into()),
                    address: "jane@example.test".into()
                },
                Address {
                    name: None,
                    address: "eve@example.test".into()
                },
            ]
        );
        assert_eq!(
            parsed.cc,
            vec![
                Address {
                    name: Some("Carol".into()),
                    address: "carol@example.test".into()
                },
                Address {
                    name: None,
                    address: "dan@example.test".into()
                },
            ]
        );
        for raw in [
            "Subject: Missing\n\nBody",
            "From: not a valid address\n\nBody",
        ] {
            let parsed = parse(raw.as_bytes()).unwrap();
            assert_eq!(parsed.from, None);
            assert!(parsed.to.is_empty());
            assert!(parsed.cc.is_empty());
        }
        assert_eq!(
            parse(b"From: solo@example.test\n\nBody")
                .unwrap()
                .from
                .unwrap()
                .name,
            None
        );
    }

    #[test]
    fn bad_first_plain_text_is_undecodable_not_replaced_by_later_text() {
        for bad in [
            b"Content-Type: text/plain; charset=unknown-charset\n\nx".as_slice(),
            b"Content-Type: text/plain; charset=utf-8\n\n\xff",
            b"Content-Type: text/plain; charset=us-ascii\n\n\xff",
            b"Content-Transfer-Encoding: x-unknown\n\nx",
            b"Content-Transfer-Encoding: base64\n\n!!!!",
        ] {
            let parsed = parse(bad).unwrap();
            assert_eq!(parsed.body, None);
            assert_eq!(parsed.body_state, BodyState::Undecodable);
        }
        let raw = multipart(&[
            "Content-Type: text/plain; charset=unknown\r\n\nbad",
            "Content-Type: text/plain\r\n\nnot a fallback",
        ]);
        assert_eq!(
            parse(raw.as_bytes()).unwrap().body_state,
            BodyState::Undecodable
        );
    }

    #[test]
    fn body_cap_keeps_utf8_prefix_and_flags_once() {
        let prefix = "x".repeat(caps::BODY_BYTES - 1);
        let raw = format!("Content-Type: text/plain; charset=utf-8\n\n{prefix}😀trailing");
        let parsed = parse(raw.as_bytes()).unwrap();
        assert_eq!(parsed.body.as_deref(), Some(prefix.as_str()));
        assert_eq!(parsed.truncated, vec!["body"]);
        assert_eq!(parsed.body_state, BodyState::Ok);
        let escaped = format!("\n\n{}", "\n".repeat(caps::BODY_BYTES));
        assert_eq!(
            parse(escaped.as_bytes()).unwrap().body.unwrap().len(),
            caps::BODY_BYTES / 2
        );
    }

    #[test]
    fn nesting_and_size_limits_refuse_on_default_test_thread_stack() {
        // No larger thread is spawned: this executes on the harness's normal
        // test-thread stack, even though the input has ten thousand levels.
        let mut nested = String::new();
        for level in 0..10_000 {
            nested.push_str(&format!(
                "Content-Type: multipart/mixed; boundary=b{level}\r\n\r\n--b{level}\r\n"
            ));
        }
        nested.push_str("Content-Type: text/plain\r\n\r\nleaf");
        for level in (0..10_000).rev() {
            nested.push_str(&format!("\r\n--b{level}--\r\n"));
        }
        assert_eq!(parse(nested.as_bytes()), Err(ParseError::NestingTooDeep));
        let oversized = vec![b'x'; MAX_MESSAGE_BYTES + 1];
        assert_eq!(parse(&oversized), Err(ParseError::InputTooLarge));
    }

    #[test]
    fn malformed_multipart_and_part_count_are_bounded() {
        assert_eq!(
            parse(b"Content-Type: multipart/mixed\n\nx"),
            Err(ParseError::Malformed)
        );
        assert_eq!(
            parse(b"Content-Type: multipart/mixed; boundary=b\n\n--b\n\nx"),
            Err(ParseError::Malformed)
        );
        let parts = vec!["\r\nx"; MAX_MIME_PARTS];
        assert_eq!(
            parse(multipart(&parts).as_bytes()),
            Err(ParseError::TooManyParts)
        );
    }
}
