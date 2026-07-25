//! Pure URL parsing and transition-target reuse for the browser connector.
//!
//! URL parsing is intentionally independent of a browser, resolver, or connector.
//! A transition target is parsed once and the resulting immutable object is shared
//! by retries. This keeps a retry from observing a different interpretation of the
//! same caller-supplied URL.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

const MAX_URL_BYTES: usize = 4096;
const MAX_SCHEME_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlParseError {
    Empty,
    TooLong,
    MissingScheme,
    InvalidScheme,
    MissingAuthority,
    UserinfoNotAllowed,
    InvalidHost,
    InvalidPort,
    InvalidEscape,
    InvalidCharacter,
    UnsupportedAuthorityForm,
}

impl fmt::Display for UrlParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "empty URL",
            Self::TooLong => "URL exceeds 4096 bytes",
            Self::MissingScheme => "absolute URL scheme is missing",
            Self::InvalidScheme => "URL scheme is invalid",
            Self::MissingAuthority => "URL authority is missing",
            Self::UserinfoNotAllowed => "URL userinfo is not allowed",
            Self::InvalidHost => "URL host is invalid",
            Self::InvalidPort => "URL port is invalid",
            Self::InvalidEscape => "URL escape is invalid",
            Self::InvalidCharacter => "URL contains an invalid character",
            Self::UnsupportedAuthorityForm => "URL authority form is unsupported",
        })
    }
}

impl std::error::Error for UrlParseError {}

/// An immutable, canonical absolute URL.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalUrl {
    canonical: String,
    scheme: String,
    host: String,
    port: Option<u16>,
    path: String,
    query: Option<String>,
    fragment: Option<String>,
}

impl CanonicalUrl {
    pub fn parse(input: &str) -> Result<Self, UrlParseError> {
        parse_canonical_url(input)
    }

    pub fn as_str(&self) -> &str {
        &self.canonical
    }
    pub fn scheme(&self) -> &str {
        &self.scheme
    }
    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn port(&self) -> Option<u16> {
        self.port
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }
    pub fn fragment(&self) -> Option<&str> {
        self.fragment.as_deref()
    }
    pub fn is_http(&self) -> bool {
        self.scheme == "http" || self.scheme == "https"
    }

    /// Return the RFC 6454 origin used by transition authorization.
    pub fn origin(&self) -> String {
        let authority = self.host.clone();
        let default_port = match self.scheme.as_str() {
            "http" => Some(80),
            "https" => Some(443),
            _ => None,
        };
        match self.port.filter(|port| Some(*port) != default_port) {
            Some(port) => format!("{}://{}:{port}", self.scheme, authority),
            None => format!("{}://{authority}", self.scheme),
        }
    }

    /// Return the host as a binary address when it is a canonical IP literal.
    pub fn literal_address(&self) -> Option<std::net::IpAddr> {
        if self.host.starts_with('[') {
            self.host[1..self.host.len() - 1]
                .parse::<Ipv6Addr>()
                .ok()
                .map(std::net::IpAddr::V6)
        } else {
            self.host.parse::<Ipv4Addr>().ok().map(std::net::IpAddr::V4)
        }
    }
}

/// Parse one absolute URL into the immutable canonical representation.
pub fn parse_canonical_url(input: &str) -> Result<CanonicalUrl, UrlParseError> {
    if input.is_empty() {
        return Err(UrlParseError::Empty);
    }
    if input.len() > MAX_URL_BYTES {
        return Err(UrlParseError::TooLong);
    }
    if input
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == b' ' || byte == b'\t')
    {
        return Err(UrlParseError::InvalidCharacter);
    }

    let colon = input.find(':').ok_or(UrlParseError::MissingScheme)?;
    if colon == 0 || colon > MAX_SCHEME_BYTES {
        return Err(UrlParseError::InvalidScheme);
    }
    let source_scheme = &input[..colon];
    if !source_scheme.bytes().enumerate().all(|(index, byte)| {
        if index == 0 {
            byte.is_ascii_alphabetic()
        } else {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
        }
    }) {
        return Err(UrlParseError::InvalidScheme);
    }
    let scheme = source_scheme.to_ascii_lowercase();
    let after_scheme = &input[colon + 1..];
    let authority_and_tail = after_scheme
        .strip_prefix("//")
        .ok_or(UrlParseError::MissingAuthority)?;
    let authority_end = authority_and_tail
        .find(['/', '?', '#'])
        .unwrap_or(authority_and_tail.len());
    let authority = &authority_and_tail[..authority_end];
    if authority.is_empty() {
        return Err(UrlParseError::MissingAuthority);
    }
    if authority.contains('@') {
        return Err(UrlParseError::UserinfoNotAllowed);
    }

    let (host, port) = parse_authority(authority)?;
    let tail = &authority_and_tail[authority_end..];
    let (before_fragment, fragment) = match tail.split_once('#') {
        Some((before, fragment)) => (before, Some(fragment.to_string())),
        None => (tail, None),
    };
    let (path_source, query) = match before_fragment.split_once('?') {
        Some((path, query)) => (path, Some(query.to_string())),
        None => (before_fragment, None),
    };
    validate_component(path_source)?;
    if let Some(query) = &query {
        validate_component(query)?;
    }
    if let Some(fragment) = &fragment {
        validate_component(fragment)?;
    }
    let path = if path_source.is_empty() {
        "/".to_string()
    } else {
        path_source.to_string()
    };

    let default_port = match scheme.as_str() {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    };
    let canonical_port = port.filter(|candidate| Some(*candidate) != default_port);
    let authority = host.clone();
    let mut canonical = format!("{scheme}://{authority}");
    if let Some(port) = canonical_port {
        canonical.push(':');
        canonical.push_str(&port.to_string());
    }
    canonical.push_str(&path);
    if let Some(query) = &query {
        canonical.push('?');
        canonical.push_str(query);
    }
    if let Some(fragment) = &fragment {
        canonical.push('#');
        canonical.push_str(fragment);
    }

    Ok(CanonicalUrl {
        canonical,
        scheme,
        host,
        port: canonical_port,
        path,
        query,
        fragment,
    })
}

/// Compatibility spelling for callers that treat parsing as a URL operation.
pub fn parse_url(input: &str) -> Result<CanonicalUrl, UrlParseError> {
    parse_canonical_url(input)
}

fn parse_authority(authority: &str) -> Result<(String, Option<u16>), UrlParseError> {
    if authority.starts_with('[') {
        let close = authority.find(']').ok_or(UrlParseError::InvalidHost)?;
        let inside = &authority[1..close];
        let address = inside
            .parse::<Ipv6Addr>()
            .map_err(|_| UrlParseError::InvalidHost)?;
        let rest = &authority[close + 1..];
        let port = if rest.is_empty() {
            None
        } else {
            Some(parse_port(
                rest.strip_prefix(':').ok_or(UrlParseError::InvalidPort)?,
            )?)
        };
        return Ok((format!("[{}]", address), port));
    }
    if authority.contains('[')
        || authority.contains(']')
        || authority.contains(':') && authority.matches(':').count() > 1
    {
        return Err(UrlParseError::UnsupportedAuthorityForm);
    }
    let (host_source, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(parse_port(port)?)),
        None => (authority, None),
    };
    if host_source.is_empty() {
        return Err(UrlParseError::InvalidHost);
    }
    let mut host = host_source.to_ascii_lowercase();
    if host.ends_with('.') {
        host.pop();
    }
    if host.is_empty() || host.len() > 253 || host.contains('%') || !host.is_ascii() {
        return Err(UrlParseError::InvalidHost);
    }
    // Numeric-looking dotted hosts are IP literals, not alternate integer forms.
    if host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        let address = host
            .parse::<Ipv4Addr>()
            .map_err(|_| UrlParseError::InvalidHost)?;
        if address.to_string() != host {
            return Err(UrlParseError::InvalidHost);
        }
        return Ok((host, port));
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(UrlParseError::InvalidHost);
        }
    }
    Ok((host, port))
}

fn parse_port(port: &str) -> Result<u16, UrlParseError> {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(UrlParseError::InvalidPort);
    }
    let value = port
        .parse::<u32>()
        .map_err(|_| UrlParseError::InvalidPort)?;
    if value > u16::MAX as u32 {
        return Err(UrlParseError::InvalidPort);
    }
    Ok(value as u16)
}

fn validate_component(component: &str) -> Result<(), UrlParseError> {
    let bytes = component.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return Err(UrlParseError::InvalidEscape);
            }
            index += 3;
        } else if bytes[index].is_ascii_control() {
            return Err(UrlParseError::InvalidCharacter);
        } else {
            index += 1;
        }
    }
    Ok(())
}

/// Cache of parsed transition targets. Both successful and failed parses are
/// cached, so a retry cannot trigger a second parse or a second interpretation.
#[derive(Debug, Default)]
pub struct TransitionTargetCache {
    parsed: BTreeMap<String, Result<Arc<CanonicalUrl>, UrlParseError>>,
    parse_count: usize,
}

impl TransitionTargetCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parse_once(&mut self, raw: &str) -> Result<Arc<CanonicalUrl>, UrlParseError> {
        if let Some(parsed) = self.parsed.get(raw) {
            return parsed.clone();
        }
        self.parse_count += 1;
        let parsed = parse_canonical_url(raw).map(Arc::new);
        self.parsed.insert(raw.to_string(), parsed.clone());
        parsed
    }

    pub fn parsed_target(&mut self, raw: &str) -> Result<TransitionTarget, UrlParseError> {
        self.parse_once(raw).map(TransitionTarget::new)
    }

    pub fn parse_count(&self) -> usize {
        self.parse_count
    }
    pub fn len(&self) -> usize {
        self.parsed.len()
    }
    pub fn is_empty(&self) -> bool {
        self.parsed.is_empty()
    }
}

/// An immutable parsed target carried from an invocation to every retry.
#[derive(Debug, Clone)]
pub struct TransitionTarget {
    url: Arc<CanonicalUrl>,
    attempts: usize,
}

impl TransitionTarget {
    fn new(url: Arc<CanonicalUrl>) -> Self {
        Self { url, attempts: 0 }
    }
    pub fn url(&self) -> &CanonicalUrl {
        &self.url
    }
    pub fn shared_url(&self) -> Arc<CanonicalUrl> {
        Arc::clone(&self.url)
    }
    pub fn attempts(&self) -> usize {
        self.attempts
    }
    pub fn retry(&self) -> Self {
        Self {
            url: Arc::clone(&self.url),
            attempts: self.attempts + 1,
        }
    }
    pub fn same_parsed_object(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.url, &other.url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_once_and_reuses_the_object_for_retries() {
        let mut cache = TransitionTargetCache::new();
        let first = cache.parsed_target("HTTPS://Example.COM:443").unwrap();
        let retry = first.retry();
        let second = cache.parsed_target("HTTPS://Example.COM:443").unwrap();
        assert_eq!(first.url().as_str(), "https://example.com/");
        assert!(first.same_parsed_object(&retry));
        assert!(first.same_parsed_object(&second));
        assert_eq!(cache.parse_count(), 1);
    }

    #[test]
    fn rejects_userinfo_and_noncanonical_numeric_hosts() {
        assert_eq!(
            CanonicalUrl::parse("https://u:p@example.com"),
            Err(UrlParseError::UserinfoNotAllowed)
        );
        assert_eq!(
            CanonicalUrl::parse("https://0177.0.0.1"),
            Err(UrlParseError::InvalidHost)
        );
    }
}
