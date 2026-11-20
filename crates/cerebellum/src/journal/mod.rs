//! Audit journal, policy events, and late-event delivery.
//!
//! This module implements the browser plane's journal surface and the closed
//! `ck-browser-journal/v7` entry contract. It owns durable allocation and
//! storage, reservations and transition pins, dispatch commitment, recovery,
//! observations recorded as evidence for actions, policy events, audit
//! obligations, and live-session late-event delivery.
//!
//! Invocation-bound pins, profile association, administration, manifest
//! gating, and strict bind-fact validation build on this machinery from
//! `src/journal_pin.rs` and `src/journal_admin.rs`.
//!
//! # Durability model
//!
//! The specification requires a durable allocator, atomic capacity reservation,
//! transition markers, export snapshots, retention mutation, and crash
//! recovery. The concrete storage substrate is a release-time dependency; this
//! implementation models durability with an in-memory store whose every
//! mutating step is an explicit, atomic "commit". Fault injection lets tests
//! fail a specific durable-write step so the marker, recovery, and cancellation
//! contracts can be exercised without a real disk. Crash/restart is modeled by
//! dropping invocation-only state (handles and tokens) and re-running recovery
//! against the surviving durable records.
//!
//! # Serialization sizing
//!
//! Export encoding is newline-delimited RFC 8785 JSON Canonicalization Scheme
//! (JCS) JSON, each line terminated by exactly one LF. Canonical JCS byte
//! production is a release dependency; for capacity accounting this module
//! measures the UTF-8 length of the deterministic `serde_json` encoding plus
//! the terminating LF. Callers that require exact JCS bytes substitute the
//! canonicalizer at the export seam without changing the accounting logic.

pub mod call_records;
pub mod core_adapter;
pub mod late_events;
pub mod recovery;
pub mod reservation;
pub mod retention;
pub mod store;

pub use cerebellum_core::journal::CallOriginRecord;
use serde::{Deserialize, Serialize};

/// The default journal entry `format_version`. Public-web-baseline entries use
/// v8 and fill entries use v9 instead.
///
/// v7 added the optional `identity.origin` member: the caller behind a relayed
/// call. Entries of v3 through v6 still decode as [`JournalEntry`].
pub const FORMAT_VERSION: &str = "ck-browser-journal/v7";
pub const BASELINE_FORMAT_VERSION: &str = "ck-browser-journal/v8";
pub const BASELINE_ENTRY_FORMAT: cerebellum_core::format_floor::DurableFormat =
    cerebellum_core::format_floor::DurableFormat::new("browser-journal-entry", 8);
/// Only fill entries use v9; ordinary writes keep their existing bytes and floor.
pub const FILL_LOGIN_FORMAT_VERSION: &str = "ck-browser-journal/v9";
pub const FILL_LOGIN_ENTRY_FORMAT: cerebellum_core::format_floor::DurableFormat =
    cerebellum_core::format_floor::DurableFormat::new("browser-journal-entry", 9);

/// The export `format_version` reported by the administration export surface.
pub const EXPORT_FORMAT_VERSION: &str = "ck-browser-journal-export/v9";

/// The greatest sequence the allocator may hand out (`9007199254740991`).
///
/// Sequences live in `1..=MAX_SEQUENCE`. Advancement past this bound is
/// exhaustion: it never wraps and produces `journal_reservation_failed`.
pub const MAX_SEQUENCE: u64 = 9_007_199_254_740_991;

/// Closed `internal_error.reason_code` vocabulary for journal entries.
///
/// `interrupted_after_dispatch` and `redaction_unavailable` are journal-only:
/// B1 never surfaces them to a caller. The remaining codes are the closed set
/// B1 may surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JournalReasonCode {
    #[serde(rename = "journal_reservation_failed")]
    JournalReservationFailed,
    #[serde(rename = "journal_entry_oversize")]
    JournalEntryOversize,
    #[serde(rename = "interrupted_after_dispatch")]
    InterruptedAfterDispatch,
    #[serde(rename = "profile_storage_unavailable")]
    ProfileStorageUnavailable,
    #[serde(rename = "result_serialization_limit")]
    ResultSerializationLimit,
    #[serde(rename = "connector_failure")]
    ConnectorFailure,
    #[serde(rename = "cdp_failure")]
    CdpFailure,
    #[serde(rename = "redaction_unavailable")]
    RedactionUnavailable,
    #[serde(rename = "internal_failure")]
    InternalFailure,
}

impl JournalReasonCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::JournalReservationFailed => "journal_reservation_failed",
            Self::JournalEntryOversize => "journal_entry_oversize",
            Self::InterruptedAfterDispatch => "interrupted_after_dispatch",
            Self::ProfileStorageUnavailable => "profile_storage_unavailable",
            Self::ResultSerializationLimit => "result_serialization_limit",
            Self::ConnectorFailure => "connector_failure",
            Self::CdpFailure => "cdp_failure",
            Self::RedactionUnavailable => "redaction_unavailable",
            Self::InternalFailure => "internal_failure",
        }
    }
}

/// The error shape returned to invocation-side callers by the journal pin.
///
/// It carries exactly one closed reason code and never exception text, platform
/// errors, oversize caller material, or implementation-specific messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalError {
    pub reason_code: JournalReasonCode,
}

impl JournalError {
    pub fn new(reason_code: JournalReasonCode) -> Self {
        Self { reason_code }
    }

    pub fn reservation_failed() -> Self {
        Self::new(JournalReasonCode::JournalReservationFailed)
    }

    pub fn internal_failure() -> Self {
        Self::new(JournalReasonCode::InternalFailure)
    }
}

/// The three journal phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    #[serde(rename = "rejected_pre_dispatch")]
    RejectedPreDispatch,
    #[serde(rename = "dispatched")]
    Dispatched,
    #[serde(rename = "policy_event")]
    PolicyEvent,
}

/// The closed browser capability vocabulary that reserves journal capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Capability {
    #[serde(rename = "browser.navigate")]
    Navigate,
    #[serde(rename = "browser.click")]
    Click,
    #[serde(rename = "browser.type")]
    Type,
    #[serde(rename = "browser.click_point")]
    ClickPoint,
    #[serde(rename = "browser.scroll")]
    Scroll,
    // The observations. Added in v3 because the four above are exactly the
    // capabilities that mutate or inject input, and the reads were being folded
    // onto Navigate -- so a snapshot of a logged-in profile persisted as a page
    // load.
    //
    // Recorded rather than skipped: these profiles hold live logins, and "which
    // pages did this agent read, and when" is the first question a compromise
    // investigation asks. An evicted old record is a capacity problem with
    // knobs; a read that was never recorded is unrecoverable.
    #[serde(rename = "browser.snapshot")]
    Snapshot,
    #[serde(rename = "browser.screenshot")]
    Screenshot,
    #[serde(rename = "browser.wait_for")]
    WaitFor,
    #[serde(rename = "browser.present")]
    Present,
    #[serde(rename = "browser.import_login")]
    ImportLogin,
    // Added in v6. A capture holds a cookie value for the first time in this
    // module, so each attempt is recorded -- never the value or a cookie name,
    // only who will hold the login, for which site, and how it ended.
    #[serde(rename = "browser.capture_login")]
    CaptureLogin,
    #[serde(rename = "browser.fill_login")]
    FillLogin,
}

impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Navigate => "browser.navigate",
            Self::Click => "browser.click",
            Self::Type => "browser.type",
            Self::ClickPoint => "browser.click_point",
            Self::Scroll => "browser.scroll",
            Self::Snapshot => "browser.snapshot",
            Self::Screenshot => "browser.screenshot",
            Self::WaitFor => "browser.wait_for",
            Self::Present => "browser.present",
            Self::ImportLogin => "browser.import_login",
            Self::CaptureLogin => "browser.capture_login",
            Self::FillLogin => "browser.fill_login",
        }
    }

    /// Whether this capability's governing observation is a text snapshot.
    pub fn governs_text_snapshot(self) -> bool {
        matches!(self, Self::Click | Self::Type)
    }

    /// Whether this capability's governing observation is a screenshot.
    pub fn governs_screenshot(self) -> bool {
        matches!(self, Self::ClickPoint)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoffJournalOutcome {
    Opened,
    LoginObserved,
    Expired,
    ClosedByCaller,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffPayload {
    pub origin: String,
    pub outcome: HandoffJournalOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cookie_names_added: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginImportPayload {
    pub origin: String,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser: Option<String>,
    pub rows: u64,
}

/// One `browser.capture_login` attempt. Carries no cookie name or value: the
/// byte count is the only fact recorded about the captured header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginCapturePayload {
    /// The origin of the login page the person was handed.
    pub origin: String,
    /// The principal that will hold the captured login.
    pub holder: String,
    /// The vault id the operator is told to store it under.
    pub credential_id: String,
    /// Length of the captured request header, zero when nothing was captured.
    pub bytes: u64,
    /// `captured`, `no_login_observed`, `expired`, `cancelled`, or
    /// `refused:<reason>`.
    pub outcome: String,
    /// Whether the throwaway profile was deleted. Absent when the attempt
    /// ended before any profile directory existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletion_succeeded: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JournalPayload {
    Handoff(HandoffPayload),
    LoginImport(LoginImportPayload),
    LoginCapture(LoginCapturePayload),
    LoginFill(LoginFillPayload),
}

/// The only facts retained about a fill. Field names are a closed enum so a
/// caller cannot accidentally record a field's value in their place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginFillPayload {
    pub outcome: String,
    /// Absent if the page was refused before its field origin was established.
    pub origin: Option<String>,
    pub filled: Vec<LoginFillField>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginFillField {
    Username,
    Password,
    Otp,
}

/// The eight B1 capability names that may appear as a policy-event
/// `initiating_capability`, plus the null case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InitiatingCapability {
    #[serde(rename = "browser.status")]
    Status,
    #[serde(rename = "browser.navigate")]
    Navigate,
    #[serde(rename = "browser.click")]
    Click,
    #[serde(rename = "browser.type")]
    Type,
    #[serde(rename = "browser.click_point")]
    ClickPoint,
    #[serde(rename = "browser.snapshot")]
    Snapshot,
    #[serde(rename = "browser.screenshot")]
    Screenshot,
    #[serde(rename = "browser.wait_for")]
    WaitFor,
}

/// Daemon-stamped journal identity.
///
/// `principal` is the canonical projection defined by the manifest-pinned Spec A
/// principal schema, never a raw identity string and never `not mcp:*`. The
/// profile facts come from the applicable B2B current-open association.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalIdentity {
    pub principal: String,
    pub conversation_key: String,
    pub agent_project_id: String,
    pub session_kind: SessionKind,
    pub profile_uuid: Option<String>,
    pub profile_name: Option<String>,
    /// The caller behind a relayed call, for attribution only; omitted when
    /// the request named none.
    #[serde(default, skip_serializing_if = "CallOriginRecord::is_absent")]
    pub origin: CallOriginRecord,
    /// The request this entry serves, handed on to the core journal so its
    /// dispatch commitment marks the request. Never exported or persisted.
    #[serde(skip)]
    pub witness: cerebellum_core::dispatch_witness::DispatchWitness,
}

/// Effective session kind, mirroring the closed Spec A enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    Primary,
    Subagent,
    Ephemeral,
}

/// Severity classification attached to a request entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Severity {
    pub tier: u8,
    pub credential: bool,
    pub financial: bool,
}

/// The grant-decision block. An allowed baseline decision names
/// `public_web_baseline`; person-issued grants retain a null reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantDecision {
    pub outcome: GrantOutcome,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantOutcome {
    Allowed,
    Denied,
    NotReached,
}

impl GrantDecision {
    pub fn not_reached() -> Self {
        Self {
            outcome: GrantOutcome::NotReached,
            reason: None,
        }
    }
}

/// The governing-observation block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GoverningObservation {
    Text {
        bytes_utf8: String,
        observation_policy: TextObservationPolicy,
    },
    ImagePngB64 {
        bytes_utf8: String,
        observation_policy: ImageObservationPolicy,
    },
    None {
        reason: NoObservationReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TextObservationPolicy {
    #[serde(rename = "ck-browser-redaction/v1")]
    RedactionV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageObservationPolicy {
    #[serde(rename = "visual_unredacted_v1")]
    VisualUnredactedV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoObservationReason {
    NoPriorObservation,
    ObservationNotRequired,
}

impl GoverningObservation {
    pub fn observation_not_required() -> Self {
        Self::None {
            reason: NoObservationReason::ObservationNotRequired,
        }
    }

    pub fn no_prior_observation() -> Self {
        Self::None {
            reason: NoObservationReason::NoPriorObservation,
        }
    }
}

/// The typed action block for a request entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    Scroll,
    Navigate {
        url_redacted: String,
        wait: NavigateWait,
    },
    Click {
        #[serde(rename = "ref")]
        reference: String,
        snapshot_id: String,
    },
    Type {
        #[serde(rename = "ref")]
        reference: String,
        snapshot_id: String,
        text_bytes_utf8: u64,
        replace: bool,
    },
    ClickPoint {
        snapshot_id: String,
        x_px: i64,
        y_px: i64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NavigateWait {
    Settle,
    None,
}

/// The locator block for a request entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Locator {
    Ref {
        #[serde(rename = "ref")]
        reference: String,
        snapshot_id: String,
        frame_path: Vec<String>,
        role: String,
        name_redacted: String,
        nth: u64,
    },
    Point {
        snapshot_id: String,
        x_px: i64,
        y_px: i64,
    },
}

/// The closed outcome-detail union for a request entry.
///
/// Normal request entries carry exactly the B1 frozen outcome and detail. The
/// journal-only exceptions are `internal_error` with `interrupted_after_dispatch`
/// (recovered dispatch commitment) and `internal_error` with
/// `redaction_unavailable` (exact reduced redactor-unavailable entry), plus the
/// deterministic oversize fallback `journal_entry_oversize`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeDetail {
    pub outcome: Outcome,
    pub detail: Detail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    InvalidRequest,
    InternalError,
    Denied,
    StaleSnapshot,
    ProfileBusy,
}

/// Closed detail block. The `reason_code` form covers every `internal_error`
/// detail; structured B1 details (e.g. `profile_busy`) carry their own fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Detail {
    ReasonCode { reason_code: JournalReasonCode },
    ProfileBusy { profile_uuid: String },
    Message { message: String },
}

impl Detail {
    pub fn reason_code(code: JournalReasonCode) -> Self {
        Self::ReasonCode { reason_code: code }
    }
}

/// A policy-event detail block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum PolicyEventDetail {
    DownloadBlocked {
        initiating_capability: Option<InitiatingCapability>,
        initiating_snapshot_id: Option<String>,
    },
    JsDialogDismissed {
        initiating_capability: Option<InitiatingCapability>,
        initiating_snapshot_id: Option<String>,
    },
    OriginTransitionBlocked {
        initiating_capability: Option<InitiatingCapability>,
        attempted_origin: String,
    },
    NetworkRequestBlocked {
        initiating_capability: Option<InitiatingCapability>,
        reason_code: String,
    },
}

/// The closed `ck-browser-journal/v7` entry.
///
/// No additional fields are permitted (`deny_unknown_fields`). For a policy
/// event, `capability`, `intent_redacted`, `requested_severity`,
/// `effective_severity`, `action`, and `locator` are null, `grant_decision` is
/// `not_reached`, `outcome` is null, and `detail` carries the event block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalEntry {
    pub format_version: String,
    pub sequence: u64,
    pub phase: Phase,
    pub identity: JournalIdentity,
    pub capability: Option<Capability>,
    pub intent_redacted: Option<String>,
    pub requested_severity: Option<Severity>,
    pub effective_severity: Option<Severity>,
    pub grant_decision: GrantDecision,
    pub governing_observation: GoverningObservation,
    pub action: Option<Action>,
    pub locator: Option<Locator>,
    pub snapshot_ids: Vec<String>,
    pub outcome: Option<Outcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<JournalPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

impl JournalEntry {
    /// The RFC 8785 JCS-plus-LF size used for capacity accounting.
    ///
    /// See the module note on serialization sizing: this measures the
    /// deterministic `serde_json` encoding plus the terminating LF byte.
    pub fn serialized_size(&self) -> u64 {
        // `serde_json::to_vec` produces a deterministic encoding for the closed
        // entry shape; the canonical JCS byte production is a release seam.
        let bytes = serde_json::to_vec(self).expect("closed entry serializes");
        (bytes.len() + 1) as u64
    }

    /// Serialize this entry as one export line: the JCS JSON followed by exactly
    /// one terminating LF.
    pub fn export_line(&self) -> String {
        let mut line = serde_json::to_string(self).expect("closed entry serializes");
        line.push('\n');
        line
    }
}

/// Manifest-bound journal deployment configuration.
///
/// `journal_max_entry_bytes <= journal_retention_bytes` and both are positive.
/// Neither release tooling nor runtime code infers missing values; absent bounds
/// keep the affected surfaces unadvertised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalConfig {
    pub journal_retention_bytes: u64,
    pub journal_max_entry_bytes: u64,
}

impl JournalConfig {
    /// Validate the ordering and positivity invariant.
    pub fn validate(&self) -> Result<(), JournalError> {
        if self.journal_retention_bytes == 0
            || self.journal_max_entry_bytes == 0
            || self.journal_max_entry_bytes > self.journal_retention_bytes
        {
            return Err(JournalError::internal_failure());
        }
        Ok(())
    }
}

/// Run a journal transition's synchronous durable write without holding up
/// the async runtime: on a multi-threaded runtime the calling worker hands its
/// other tasks to another thread while `work` waits on the disk. The caller
/// still waits for `work` to finish, so a transition stays durable before the
/// effect it guards and transitions keep their order. Elsewhere (no runtime,
/// or a single-threaded one, which cannot hand its tasks on) it runs inline.
pub(crate) fn off_worker<T>(work: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current().map(|runtime| runtime.runtime_flavor()) {
        Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(work),
        _ => work(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A journal transition waiting on a slow disk does not stop an unrelated
    /// task on the runtime's only worker.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn a_slow_journal_write_does_not_stall_the_runtime_worker() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let mut store = store::JournalStore::slow_in_memory_for_test(
            JournalConfig {
                journal_retention_bytes: 1_000_000,
                journal_max_entry_bytes: 100_000,
            },
            std::time::Duration::from_millis(500),
        )
        .unwrap();
        let beats = std::sync::Arc::new(AtomicUsize::new(0));
        let heartbeat = tokio::spawn({
            let beats = beats.clone();
            async move {
                loop {
                    beats.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let before = beats.load(Ordering::SeqCst);
        // On the worker, like a request handler; the test body itself is
        // polled on a separate thread.
        tokio::spawn(async move { store.reserve(identity(), Capability::Navigate).unwrap() })
            .await
            .unwrap();
        let during = beats.load(Ordering::SeqCst) - before;
        heartbeat.abort();
        assert!(
            during >= 10,
            "the heartbeat ran {during} times during a 500ms write"
        );
    }

    fn identity() -> JournalIdentity {
        JournalIdentity {
            witness: cerebellum_core::dispatch_witness::DispatchWitness::detached(),
            principal: "direct:agent".to_string(),
            conversation_key: "conv-1".to_string(),
            agent_project_id: "proj-1".to_string(),
            session_kind: SessionKind::Primary,
            profile_uuid: None,
            profile_name: None,
            origin: Default::default(),
        }
    }

    #[test]
    fn reason_code_round_trips_through_closed_vocabulary() {
        for code in [
            JournalReasonCode::JournalReservationFailed,
            JournalReasonCode::JournalEntryOversize,
            JournalReasonCode::InterruptedAfterDispatch,
            JournalReasonCode::RedactionUnavailable,
            JournalReasonCode::InternalFailure,
        ] {
            let json = serde_json::to_string(&code).unwrap();
            let back: JournalReasonCode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, code);
        }
    }

    #[test]
    fn entry_serialized_size_includes_terminating_lf() {
        let entry = JournalEntry {
            format_version: FORMAT_VERSION.to_string(),
            sequence: 1,
            phase: Phase::RejectedPreDispatch,
            identity: identity(),
            capability: Some(Capability::Navigate),
            intent_redacted: None,
            requested_severity: None,
            effective_severity: None,
            grant_decision: GrantDecision::not_reached(),
            governing_observation: GoverningObservation::observation_not_required(),
            action: None,
            locator: None,
            snapshot_ids: vec![],
            outcome: Some(Outcome::InternalError),
            payload: None,
            detail: Some(serde_json::json!({"reason_code":"journal_entry_oversize"})),
        };
        let line = entry.export_line();
        assert!(line.ends_with('\n'));
        assert_eq!(entry.serialized_size() as usize, line.len());
    }

    #[test]
    fn entry_rejects_unknown_fields() {
        let json = r#"{"format_version":"ck-browser-journal/v2","sequence":1,"phase":"dispatched","identity":{"principal":"p","conversation_key":"c","agent_project_id":"a","session_kind":"primary","profile_uuid":null,"profile_name":null},"capability":null,"intent_redacted":null,"requested_severity":null,"effective_severity":null,"grant_decision":{"outcome":"not_reached","reason":null},"governing_observation":{"kind":"none","reason":"observation_not_required"},"action":null,"locator":null,"snapshot_ids":[],"outcome":null,"extra":1}"#;
        let parsed: Result<JournalEntry, _> = serde_json::from_str(json);
        assert!(parsed.is_err());
    }

    #[test]
    fn config_validate_enforces_ordering_and_positivity() {
        assert!(JournalConfig {
            journal_retention_bytes: 100,
            journal_max_entry_bytes: 50,
        }
        .validate()
        .is_ok());
        assert!(JournalConfig {
            journal_retention_bytes: 50,
            journal_max_entry_bytes: 100,
        }
        .validate()
        .is_err());
        assert!(JournalConfig {
            journal_retention_bytes: 0,
            journal_max_entry_bytes: 0,
        }
        .validate()
        .is_err());
    }
}
