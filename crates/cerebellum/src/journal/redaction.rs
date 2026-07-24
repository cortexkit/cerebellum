//! Textual redaction and the exact reduced rejection paths.
//!
//! Every model-visible textual observation and every journal prose string
//! derived from caller input, page state, or policy events is processed by the
//! manifest-bound `ck-browser-redaction/v1` implementation before
//! serialization. This module defines the redactor seam, the structural
//! URL/origin reduction that precedes text redaction, and the two B2A-owned
//! exact reduced rejection paths (`journal_entry_oversize` and
//! `redaction_unavailable`) together with their marker-establishment and
//! finalization failure branches.
//!
//! Closed enums, schema and capability names, module-resolved identity values,
//! and opaque identifiers (`ref`, `snapshot_id`, `snapshot_ids`,
//! `initiating_snapshot_id`) are never passed through the text redactor; they
//! are lexically validated and copied byte-for-byte.

use crate::journal::store::{JournalStore, ReducedPath, TransitionMarker};
use crate::journal::{JournalError, JournalReasonCode};

/// The manifest-bound `ck-browser-redaction/v1` redactor seam.
///
/// The concrete recognizer set, replacement encoding, overlap precedence, and
/// redaction-before-truncation order are release dependencies; this trait is the
/// in-process surface the journal verifies for availability and invokes for each
/// covered textual value.
pub trait Redactor {
    /// Whether the redactor implementation is currently available.
    fn available(&self) -> bool;

    /// Redact one covered textual value, then UTF-8-safely truncate to
    /// `max_bytes`. Redaction always precedes truncation.
    fn redact(&self, input: &str, max_bytes: usize) -> Result<String, RedactionUnavailable>;
}

/// Failure of redactor availability, structural reduction, redaction,
/// truncation, or closed-detail construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactionUnavailable;

/// A redactor that performs no secret recognition.
///
/// Used by tests and as the fail-closed default until the manifest binds a real
/// implementation. It copies input unchanged (truncated to the byte bound) when
/// `available` is true and reports unavailable otherwise.
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

/// Truncate `input` to at most `max_bytes` UTF-8 bytes without splitting a code
/// point.
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

/// Structurally reduce a URL to its RFC 6454 ASCII origin serialization.
///
/// Userinfo, path, query, and fragment are never included. For an HTTP(S) URL
/// the result is `scheme://host[:port]` with the default port omitted; for any
/// other scheme or an unparseable input the result is the opaque origin
/// `"null"`. The returned origin string is what later passes through the text
/// redactor for `action.url_redacted` and `attempted_origin`.
pub fn reduce_url_to_origin(url: &str) -> String {
    let scheme_split = match url.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None => return "null".to_string(),
    };
    let (scheme, rest) = scheme_split;
    if scheme != "http" && scheme != "https" {
        return "null".to_string();
    }
    // Drop userinfo: everything before the last '@' that precedes the first '/'.
    let authority_and_path = rest;
    let authority = match authority_and_path.split(['/', '?', '#']).next() {
        Some(a) => a,
        None => return "null".to_string(),
    };
    let authority = match authority.rsplit_once('@') {
        Some((_userinfo, hostport)) => hostport,
        None => authority,
    };
    if authority.is_empty() {
        return "null".to_string();
    }
    // Split host and port. IPv6 literals are bracketed.
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        match stripped.find(']') {
            Some(close) => {
                let host = &authority[..close + 2];
                let port = authority[close + 2..].strip_prefix(':');
                (host.to_string(), port)
            }
            None => return "null".to_string(),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host.to_string(), Some(port)),
            None => (authority.to_string(), None),
        }
    };
    if host.is_empty() {
        return "null".to_string();
    }
    let host = host.to_ascii_lowercase();
    let default_port = if scheme == "http" { "80" } else { "443" };
    match port {
        Some(p) if !p.is_empty() && p != default_port => format!("{scheme}://{host}:{p}"),
        _ => format!("{scheme}://{host}"),
    }
}

impl JournalStore {
    /// Durably select and finalize the exact reduced `journal_entry_oversize`
    /// rejection for an established reservation.
    ///
    /// Detection of the oversize invariant sets `oversize_flag` before the
    /// marker transaction. On success the exact reduced entry is durably
    /// exportable and the caller surfaces `journal_entry_oversize`. Marker
    /// establishment failure leaves an unmarked orphan and surfaces
    /// `journal_reservation_failed` without ever surfacing
    /// `journal_entry_oversize`; the flag remains set. Post-marker finalization
    /// failure also surfaces `journal_reservation_failed` and writer recovery
    /// retries the marked exact reduced rejection.
    pub fn select_oversize_reduced(
        &mut self,
        handle: crate::journal::reservation::ReservationHandle,
    ) -> Result<JournalReasonCode, JournalError> {
        // Detection of the invariant sets the flag regardless of marker outcome.
        self.set_oversize_flag();
        self.commit_exact_reduced(
            handle,
            ReducedPath::Oversize,
            JournalReasonCode::JournalEntryOversize,
        )
    }

    /// Durably select and finalize the exact reduced `redaction_unavailable`
    /// rejection for an established reservation.
    ///
    /// On success the exact reduced entry is durably exportable with journal
    /// `detail.reason_code:"redaction_unavailable"`, but the caller surfaces
    /// `internal_failure` because `redaction_unavailable` is journal-only.
    /// Marker-establishment and post-marker finalization failures behave as for
    /// the oversize path (without touching `oversize_flag`).
    pub fn select_redaction_unavailable_reduced(
        &mut self,
        handle: crate::journal::reservation::ReservationHandle,
    ) -> Result<JournalReasonCode, JournalError> {
        self.commit_exact_reduced(
            handle,
            ReducedPath::RedactionUnavailable,
            JournalReasonCode::InternalFailure,
        )
    }

    /// Shared marker-establishment and finalization for both exact reduced
    /// paths. Returns the caller-visible reason code on durable success.
    fn commit_exact_reduced(
        &mut self,
        handle: crate::journal::reservation::ReservationHandle,
        path: ReducedPath,
        caller_visible: JournalReasonCode,
    ) -> Result<JournalReasonCode, JournalError> {
        let seq = handle.sequence();

        // Idempotence: if the exact reduced entry is already finalized, succeed.
        if let Some(existing) = self.entry(seq) {
            let capability = existing
                .capability
                .unwrap_or(crate::journal::Capability::Navigate);
            let expected = self.build_exact_reduced(seq, &existing.identity, capability, path);
            return if existing == &expected {
                Ok(caller_visible)
            } else {
                Err(JournalError::internal_failure())
            };
        }

        let record = self
            .reservation(seq)
            .ok_or_else(JournalError::internal_failure)?
            .clone();
        // A marked reservation is recovery-owned.
        if record.marker.is_some() {
            return Err(JournalError::internal_failure());
        }

        let identity = record.identity.clone();
        let capability = record.capability;
        let entry = self.build_exact_reduced(seq, &identity, capability, path);

        // Durably establish the exact-reduced marker. Failure leaves an unmarked
        // orphan; no rejection finalization is attempted.
        if self.faults.take("establish_marker") {
            return Err(JournalError::reservation_failed());
        }
        self.reservation_mut(seq)
            .expect("reservation present")
            .marker = Some(TransitionMarker::ExactReduced {
            path,
            entry: Box::new(entry.clone()),
        });

        // Attempt to finalize the exact reduced rejection.
        if self.faults.take("commit_rejection") {
            // Reservation remains active, marked, charged; writer recovery
            // retries the marked exact reduced rejection.
            return Err(JournalError::reservation_failed());
        }
        self.insert_finalized(entry)?;
        Ok(caller_visible)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::reservation::ReservationHandle;
    use crate::journal::{Capability, JournalConfig, JournalIdentity, SessionKind};

    fn identity() -> JournalIdentity {
        JournalIdentity {
            principal: "direct:agent".to_string(),
            conversation_key: "conv".to_string(),
            agent_project_id: "proj".to_string(),
            session_kind: SessionKind::Primary,
            profile_uuid: None,
            profile_name: None,
        }
    }

    fn store() -> JournalStore {
        JournalStore::new(JournalConfig {
            journal_retention_bytes: 1_000_000,
            journal_max_entry_bytes: 100_000,
        })
        .unwrap()
    }

    #[test]
    fn url_reduction_strips_userinfo_path_query_fragment() {
        assert_eq!(
            reduce_url_to_origin("https://user:pw@Example.COM:8443/path?q=1#frag"),
            "https://example.com:8443"
        );
        assert_eq!(
            reduce_url_to_origin("http://example.com:80/x"),
            "http://example.com"
        );
        assert_eq!(
            reduce_url_to_origin("https://example.org"),
            "https://example.org"
        );
        assert_eq!(reduce_url_to_origin("file:///etc/passwd"), "null");
        assert_eq!(reduce_url_to_origin("not a url"), "null");
    }

    #[test]
    fn utf8_safe_truncate_never_splits_a_code_point() {
        let s = "héllo"; // é is two bytes
        let truncated = utf8_safe_truncate(s, 2);
        assert_eq!(truncated, "h");
        assert_eq!(utf8_safe_truncate(s, 100), s);
    }

    #[test]
    fn oversize_reduced_success_sets_flag_and_surfaces_oversize() {
        let mut store = store();
        let handle = store.reserve(identity(), Capability::Navigate).unwrap();
        let code = store.select_oversize_reduced(handle).unwrap();
        assert_eq!(code, JournalReasonCode::JournalEntryOversize);
        assert!(store.oversize_flag());
        let export = store.export();
        assert!(export.contains("journal_entry_oversize"));
        assert!(export.contains("rejected_pre_dispatch"));
    }

    #[test]
    fn oversize_marker_failure_surfaces_reservation_failed_and_keeps_flag() {
        let mut store = store();
        let handle = store.reserve(identity(), Capability::Navigate).unwrap();
        store.faults.arm("establish_marker", 1);
        let err = store.select_oversize_reduced(handle).unwrap_err();
        assert_eq!(err.reason_code, JournalReasonCode::JournalReservationFailed);
        // Flag remains set even though no entry was exported.
        assert!(store.oversize_flag());
        assert!(!store.export().contains("journal_entry_oversize"));
        // The reservation is an unmarked orphan.
        assert!(store
            .reservation(handle.sequence())
            .unwrap()
            .marker
            .is_none());
    }

    #[test]
    fn oversize_post_marker_finalization_failure_leaves_marked_reservation() {
        let mut store = store();
        let handle = store.reserve(identity(), Capability::Navigate).unwrap();
        store.faults.arm("commit_rejection", 1);
        let err = store.select_oversize_reduced(handle).unwrap_err();
        assert_eq!(err.reason_code, JournalReasonCode::JournalReservationFailed);
        // Marked for recovery retry of the exact reduced rejection.
        let record = store.reservation(handle.sequence()).unwrap();
        assert!(matches!(
            record.marker,
            Some(TransitionMarker::ExactReduced {
                path: ReducedPath::Oversize,
                ..
            })
        ));
        assert!(!store.export().contains("journal_entry_oversize"));
    }

    #[test]
    fn redaction_unavailable_success_surfaces_internal_failure() {
        let mut store = store();
        let handle = store.reserve(identity(), Capability::Navigate).unwrap();
        let code = store.select_redaction_unavailable_reduced(handle).unwrap();
        assert_eq!(code, JournalReasonCode::InternalFailure);
        let export = store.export();
        // Journal detail carries the journal-only code.
        assert!(export.contains("redaction_unavailable"));
        assert!(!store.oversize_flag());
    }

    #[test]
    fn redaction_unavailable_marker_failure_exports_no_entry() {
        let mut store = store();
        let handle = store.reserve(identity(), Capability::Navigate).unwrap();
        store.faults.arm("establish_marker", 1);
        let err = store
            .select_redaction_unavailable_reduced(handle)
            .unwrap_err();
        assert_eq!(err.reason_code, JournalReasonCode::JournalReservationFailed);
        assert!(!store.export().contains("redaction_unavailable"));
    }

    #[test]
    fn passthrough_redactor_reports_availability() {
        let on = PassthroughRedactor { available: true };
        let off = PassthroughRedactor { available: false };
        assert!(on.available());
        assert!(!off.available());
        assert!(on.redact("secret", 100).is_ok());
        assert!(off.redact("secret", 100).is_err());
    }

    #[test]
    fn exact_reduced_is_idempotent_after_success() {
        let mut store = store();
        let handle: ReservationHandle = store.reserve(identity(), Capability::Navigate).unwrap();
        store.select_oversize_reduced(handle).unwrap();
        let code = store.select_oversize_reduced(handle).unwrap();
        assert_eq!(code, JournalReasonCode::JournalEntryOversize);
        assert_eq!(store.export().lines().count(), 1);
    }
}
