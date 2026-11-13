//! Apple Mail's decimal byte-count framing around an RFC 5322 message.

use crate::mime;

pub const MAX_EMLX_BYTES: usize = mime::MAX_MESSAGE_BYTES + 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    InputTooLarge,
    InvalidFrame,
    Mime(mime::ParseError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Frame<'a> {
    pub message: &'a [u8],
    /// Opaque trailing Mail metadata, never passed to the MIME decoder.
    pub metadata: &'a [u8],
}

pub fn frame(input: &[u8]) -> Result<Frame<'_>, ParseError> {
    if input.len() > MAX_EMLX_BYTES {
        return Err(ParseError::InputTooLarge);
    }
    let newline = input
        .iter()
        .take(22)
        .position(|b| *b == b'\n')
        .ok_or(ParseError::InvalidFrame)?;
    let count = input[..newline]
        .strip_suffix(b"\r")
        .unwrap_or(&input[..newline]);
    if count.is_empty() || !count.iter().all(u8::is_ascii_digit) {
        return Err(ParseError::InvalidFrame);
    }
    let mut length = 0usize;
    for digit in count {
        length = length
            .checked_mul(10)
            .and_then(|n| n.checked_add(usize::from(digit - b'0')))
            .ok_or(ParseError::InvalidFrame)?;
    }
    if length > mime::MAX_MESSAGE_BYTES {
        return Err(ParseError::InputTooLarge);
    }
    if length == 0 {
        return Err(ParseError::InvalidFrame);
    }
    let content = &input[newline + 1..];
    let message = content.get(..length).ok_or(ParseError::InvalidFrame)?;
    Ok(Frame {
        message,
        metadata: &content[length..],
    })
}

pub fn parse(input: &[u8]) -> Result<mime::Message, ParseError> {
    mime::parse(frame(input)?.message).map_err(ParseError::Mime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::items::{Address, BodyState};

    #[test]
    fn built_emlx_frames_bytes_and_parses_headers_and_mime_parts() {
        let message = concat!(
            "From: Ada <ada@example.test>\r\n",
            "To: bob@example.test\r\n",
            "Subject: Built fixture\r\n",
            "Content-Type: multipart/alternative; boundary=b\r\n\r\n",
            "--b\r\nContent-Type: text/html\r\n\r\n<p>HTML</p>\r\n",
            "--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\ncafé 😀\r\n--b--\r\n"
        );
        let input = format!(
            "{}\n{message}<?xml version=\"1.0\"?><plist>not body</plist>",
            message.len()
        );
        let framed = frame(input.as_bytes()).unwrap();
        assert_eq!(framed.message, message.as_bytes());
        assert!(framed.metadata.starts_with(b"<?xml"));
        let decoded = parse(input.as_bytes()).unwrap();
        assert_eq!(decoded.subject.as_deref(), Some("Built fixture"));
        assert_eq!(
            decoded.from,
            Some(Address {
                name: Some("Ada".into()),
                address: "ada@example.test".into()
            })
        );
        assert!(decoded
            .headers
            .iter()
            .any(|h| h.name == "Subject" && h.value == "Built fixture"));
        assert_eq!(
            decoded
                .parts
                .iter()
                .map(|p| (p.parent, p.mime_type.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (None, "multipart/alternative"),
                (Some(0), "text/html"),
                (Some(0), "text/plain")
            ]
        );
        assert_eq!(decoded.body.as_deref(), Some("café 😀"));
        assert_eq!(decoded.body_state, BodyState::Ok);
    }

    #[test]
    fn truncated_and_garbled_framing_refuses_without_panicking() {
        for input in [
            b"".as_slice(),
            b"1",
            b"0\n",
            b"-1\nx",
            b"+1\nx",
            b"1x\nx",
            b"99\nx",
            b"18446744073709551616\nx",
        ] {
            assert!(frame(input).is_err());
        }
        let valid = b"13\nSubject: x\n\nx";
        for end in 0..valid.len() {
            assert!(frame(&valid[..end]).is_err());
        }
        assert!(frame(valid).is_ok());
        for byte in 0..=255u8 {
            let input = [byte, b'\n', 0xff];
            let _ = frame(&input);
            let _ = parse(&input);
        }
        assert_eq!(
            frame(format!("{}\n", mime::MAX_MESSAGE_BYTES + 1).as_bytes()),
            Err(ParseError::InputTooLarge)
        );
        assert_eq!(frame(b"1\r\nx").unwrap().message, b"x");
    }
}
