//! Define the browser redaction policy and convert redaction results into the
//! compatibility API's simpler result types.

use super::store::JournalStore;
use super::{JournalError, JournalReasonCode};

pub trait Redactor {
    fn available(&self) -> bool;
    fn redact(&self, input: &str, max_bytes: usize) -> Result<String, RedactionUnavailable>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactionUnavailable;

#[derive(Debug, Clone, Copy)]
pub struct PassthroughRedactor {
    pub available: bool,
}

impl Redactor for PassthroughRedactor {
    fn available(&self) -> bool {
        self.available
    }

    fn redact(&self, input: &str, max_bytes: usize) -> Result<String, RedactionUnavailable> {
        if !self.available {
            return Err(RedactionUnavailable);
        }
        Ok(utf8_safe_truncate(input, max_bytes))
    }
}

pub fn utf8_safe_truncate(input: &str, max_bytes: usize) -> String {
    if input.len() <= max_bytes {
        return input.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    input[..end].to_string()
}

pub fn reduce_url_to_origin(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None => return "null".to_string(),
    };
    if scheme != "http" && scheme != "https" {
        return "null".to_string();
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, value)| value);
    if authority.is_empty() {
        return "null".to_string();
    }
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        let Some(close) = stripped.find(']') else {
            return "null".to_string();
        };
        (
            &authority[..close + 2],
            authority[close + 2..].strip_prefix(':'),
        )
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return "null".to_string();
    }
    let host = host.to_ascii_lowercase();
    let default_port = if scheme == "http" { "80" } else { "443" };
    match port {
        Some(port) if !port.is_empty() && port != default_port => {
            format!("{scheme}://{host}:{port}")
        }
        _ => format!("{scheme}://{host}"),
    }
}

impl JournalStore {
    pub fn select_oversize_reduced(
        &mut self,
        handle: super::reservation::ReservationHandle,
    ) -> Result<JournalReasonCode, JournalError> {
        self.select_reduced(
            handle,
            JournalReasonCode::JournalEntryOversize,
            JournalReasonCode::JournalEntryOversize,
        )
    }

    pub fn select_redaction_unavailable_reduced(
        &mut self,
        handle: super::reservation::ReservationHandle,
    ) -> Result<JournalReasonCode, JournalError> {
        self.select_reduced(
            handle,
            JournalReasonCode::RedactionUnavailable,
            JournalReasonCode::InternalFailure,
        )
    }
}
