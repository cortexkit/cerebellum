//! Optional redaction policy binding.
//!
//! A missing policy is reported as unavailable. No implementation in this
//! module substitutes copying or truncating input, because doing so could make
//! sensitive material durable.

/// Failure of the configured redaction policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactionUnavailable;

/// Plane-neutral redaction contract.
pub trait Redactor {
    fn available(&self) -> bool;
    fn redact(&self, input: &str, max_bytes: usize) -> Result<String, RedactionUnavailable>;
}

impl Redactor for () {
    fn available(&self) -> bool {
        false
    }

    fn redact(&self, _input: &str, _max_bytes: usize) -> Result<String, RedactionUnavailable> {
        Err(RedactionUnavailable)
    }
}

impl<T: Redactor + ?Sized> Redactor for Box<T> {
    fn available(&self) -> bool {
        (**self).available()
    }

    fn redact(&self, input: &str, max_bytes: usize) -> Result<String, RedactionUnavailable> {
        (**self).redact(input, max_bytes)
    }
}

/// Redact input and then truncate without splitting a UTF-8 code point.
pub fn redact_then_truncate<R: Redactor>(
    redactor: Option<&R>,
    input: &str,
    max_bytes: usize,
) -> Result<String, RedactionUnavailable> {
    let redactor = redactor
        .filter(|policy| policy.available())
        .ok_or(RedactionUnavailable)?;
    let redacted = redactor.redact(input, max_bytes)?;
    if redacted.len() <= max_bytes {
        return Ok(redacted);
    }
    let mut end = max_bytes;
    while end > 0 && !redacted.is_char_boundary(end) {
        end -= 1;
    }
    Ok(redacted[..end].to_string())
}
