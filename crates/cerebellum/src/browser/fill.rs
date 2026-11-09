//! `browser.fill_login`: fill a login saved in the vault into a form in the
//! agent's own browser, without the model ever seeing the password.
//!
//! The agent names only the saved login and the snapshot refs of the form's
//! fields. The order is what keeps a refused fill from ever holding a
//! secret:
//!
//! 1. The fields are resolved and checked first: a password input, a username
//!    or email input in the same form, an optional one-time-code input, all in
//!    frames of one https origin. Nothing is asked of the vault until these
//!    checks pass.
//! 2. The vault (a [`LoginMaterialSource`]) is asked for the login, for the
//!    origin those fields' frames have. It answers with the login, a request
//!    for the person's approval, or a refusal.
//! 3. The fields are checked again on the live page, in the same CDP call as
//!    the insertion, and the values inserted. If anything changed, whatever was
//!    filled is cleared and the values are dropped.
//!
//! The values live only in [`Zeroizing`] buffers. Replies say which fields
//! were filled and for which origin, never what went in them. After a fill,
//! the tab is in a window (see [`FillWindow`]): screenshots are refused, and
//! text read from the page has the filled fields masked and the password
//! removed.

use std::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};
use zeroize::{Zeroize, Zeroizing};

use super::{
    bounded_call_reply_schema, browser_result_outcome_schema, closed_object,
    collect_result_violations, context_result_schema, enum_schema, integer_schema,
    map_navigation_drive_error, map_snapshot_error, refusal_detail_schema, required_string,
    string_array_schema, string_schema, BrowserCapability, BrowserError, BrowserPlane,
    JournalReasonCode,
};
use crate::classification::{NonTypeClassificationRecord, TargetKind};
use crate::snapshot_store::{self, BackendNodeIdentity, CommittedDocument, FrameDocument};
use cerebellum_computer::platform::vocabulary::{
    CapabilityResultValidationError, CapabilityResultViolation,
};
use cerebellum_core::identity::RouteIdentity;

pub const FILL_LOGIN: &str = "browser.fill_login";

/// Production admission is on: a plane built for a running module is given
/// the live vault source and serves `browser.fill_login`. Planes built for
/// tests get no source unless a test installs one.
pub const FILL_LOGIN_ENABLED: bool = true;

/// The live vault source. Construction does no I/O; admission remains separate.
pub const PRODUCTION_LOGIN_MATERIAL_SOURCE: fn(PathBuf, String) -> Arc<dyn LoginMaterialSource> =
    crate::login_capture::secret_use::production_source;

/// The source a plane built for a running module is given.
pub fn production_login_material_source(
    path: PathBuf,
    module_id: String,
) -> Arc<dyn LoginMaterialSource> {
    PRODUCTION_LOGIN_MATERIAL_SOURCE(path, module_id)
}

/// `name`, when it is `browser.fill_login` and this plane serves it.
pub fn admitted<'a>(
    name: &'a str,
    plane: &BrowserPlane,
    browser_configured: bool,
) -> Option<&'a str> {
    (name == FILL_LOGIN
        && browser_configured
        && plane
            .login_material
            .as_ref()
            .is_some_and(|source| source.enabled()))
    .then_some(name)
}

/// How long after a fill the tab stays in its window at most.
pub const FILL_WINDOW: Duration = Duration::from_secs(10 * 60);

// ---------------------------------------------------------------------------
// The vault's `secret.use`
// ---------------------------------------------------------------------------

/// One `secret.use` request: `{name, coverage, stamp, target: {origin}}`.
///
/// `stamp` is the stamped scope of the route the call arrived on (the head's,
/// for a codemode run); the vault derives the asking agent from it alone.
/// `origin` is the origin of the frames holding the fields to fill, read from
/// the page, never from the agent's arguments.
#[derive(Debug, Clone, PartialEq)]
pub struct SecretUseRequest {
    pub name: String,
    pub stamp: Value,
    pub origin: String,
}

impl SecretUseRequest {
    /// Cerebellum always asks for the calling scope's own grant.
    pub const COVERAGE: &'static str = "scope";

    /// The request's params, exactly as the vault receives them.
    pub fn params(&self) -> Value {
        json!({
            "name": self.name,
            "coverage": Self::COVERAGE,
            "stamp": self.stamp,
            "target": {"origin": self.origin},
        })
    }
}

/// The vault could not be asked at all: its route is missing or failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceUnavailable;

pub type SourceFuture<'a> =
    Pin<Box<dyn Future<Output = Result<SecretUseAnswer, SourceUnavailable>> + Send + 'a>>;

/// Where login material comes from: the vault's `secret.use`.
///
/// Sources decode directly into zeroizing material, never a JSON `Value` holding
/// ordinary secret strings, and retain no copy after handing over the answer.
pub trait LoginMaterialSource: Send + Sync {
    fn secret_use(&self, request: &SecretUseRequest) -> SourceFuture<'_>;

    /// Isolated test sources are admitted; the production source uses the
    /// rollout switch even when it has already been installed on a plane.
    fn enabled(&self) -> bool {
        true
    }
}

/// A released login. Every value is wiped when this is dropped.
pub struct LoginMaterial {
    pub username: Zeroizing<String>,
    pub password: Zeroizing<String>,
    /// The current six-digit code, already computed by the vault.
    pub totp: Option<Zeroizing<String>>,
}

impl fmt::Debug for LoginMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginMaterial")
            .field("totp", &self.totp.is_some())
            .finish_non_exhaustive()
    }
}

/// The vault asks the person first. `statement_b64url` is the statement the
/// card shows, passed through unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    pub request_id: String,
    pub statement_b64url: String,
    pub expires_at_ms: u64,
}

#[derive(Debug)]
pub enum SecretUseAnswer {
    Released(LoginMaterial),
    ApprovalRequired(Approval),
    /// Unknown, not granted, the wrong origin, or any reply this does not
    /// understand. The vault answers these alike, and so does this module.
    Refused,
}

impl SecretUseAnswer {
    /// Decode the closed vault reply without allocating ordinary secret strings.
    pub fn from_wire(reply: Zeroizing<Vec<u8>>) -> Self {
        crate::login_capture::secret_use::decode_reply(&reply)
    }
}

// ---------------------------------------------------------------------------
// What crosses into the browser process
// ---------------------------------------------------------------------------

/// The three fields a login fill can write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginField {
    Username,
    Password,
    Otp,
}

impl LoginField {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Username => "username",
            Self::Password => "password",
            Self::Otp => "otp",
        }
    }

    const fn argument(self) -> &'static str {
        match self {
            Self::Username => "username_ref",
            Self::Password => "password_ref",
            Self::Otp => "otp_ref",
        }
    }
}

/// One field to fill, as the snapshot classified it, with its value.
#[derive(Clone)]
pub struct FillTarget {
    pub field: LoginField,
    pub identity: BackendNodeIdentity,
    pub classification: NonTypeClassificationRecord,
    /// The field's frame document, `None` for the main frame.
    pub frame: Option<FrameDocument>,
    pub value: Zeroizing<String>,
}

impl fmt::Debug for FillTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FillTarget")
            .field("field", &self.field)
            .field("identity", &self.identity)
            .field("frame", &self.frame)
            .finish_non_exhaustive()
    }
}

/// Everything the browser process needs to check and fill a login.
#[derive(Debug, Clone)]
pub struct FillDispatch {
    /// The main-frame document the snapshot was taken from.
    pub document: Option<CommittedDocument>,
    /// In insertion order.
    pub targets: Vec<FillTarget>,
    insertion_attempted: Arc<AtomicBool>,
}

impl FillDispatch {
    fn new(document: CommittedDocument, targets: Vec<FillTarget>) -> Self {
        Self {
            document: Some(document),
            targets,
            insertion_attempted: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Any adapter that sends a value to the renderer must call this immediately
    /// before sending it, even if the command may fail or its reply may be lost.
    pub fn mark_insertion_attempted(&self) {
        self.insertion_attempted.store(true, Ordering::Release);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FillOutcome {
    Filled,
    /// Insertion did not complete. The protection window remains installed
    /// because page script may have copied a value before rollback.
    Aborted {
        reason_code: &'static str,
    },
}

/// A field this module filled, by identity only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilledField {
    pub identity: BackendNodeIdentity,
    pub frame: Option<FrameDocument>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilledFieldsState {
    /// At least one field may still hold what was filled.
    SomeFilled,
    /// Every field is empty, or no longer in its document.
    AllEmptyOrGone,
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// Why a fill, or a read of a page holding a filled login, was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FillRefusal {
    /// A field's frame is not https, has an opaque origin, or the fields'
    /// frames are not all of one origin. Decided before the vault is asked.
    Origin {
        field: &'static str,
        reason_code: &'static str,
    },
    /// The vault will not release this login for this agent on this site.
    /// Whether the name is unknown, not shared with the agent, or saved for
    /// another site is not said, because the vault does not say it either.
    LoginUnavailable,
    /// The vault could not be asked.
    VaultUnavailable,
    /// The page changed or insertion could not be confirmed. Once insertion
    /// was attempted, reads remain protected even after rollback.
    Aborted {
        reason_code: &'static str,
        insertion_attempted: bool,
    },
    /// A screenshot of a tab holding a filled password.
    FilledPasswordOnPage,
    /// A read of a tab whose filled login has outlived its window.
    WindowExpired,
    /// The person's approval for using the login did not arrive. `asked`
    /// is false when the question could not be put to anyone.
    ApprovalNotGiven {
        decision: &'static str,
        asked: bool,
    },
    ApprovalServiceRefused(crate::cingulate_client::desk::SecretUseRefusal),
}

impl FillRefusal {
    pub(super) fn outcome(self) -> &'static str {
        match self {
            Self::VaultUnavailable => "internal_error",
            Self::Aborted { .. } => "stale_snapshot",
            Self::ApprovalNotGiven { asked: false, .. } => "consent_unavailable",
            Self::ApprovalServiceRefused(_) => "consent_unavailable",
            Self::Origin { .. }
            | Self::LoginUnavailable
            | Self::FilledPasswordOnPage
            | Self::WindowExpired
            | Self::ApprovalNotGiven { asked: true, .. } => "authorization_denied",
        }
    }

    pub(super) fn remedy(self) -> &'static str {
        match self {
            Self::Origin { .. } => "a saved login goes only into fields whose frames are https and share one origin; choose the fields of such a form from a fresh snapshot",
            Self::LoginUnavailable => "this agent cannot use a saved login of that name on this site; check the name with the person, or ask them to share the login with this agent for this site",
            Self::VaultUnavailable => "the vault could not be reached; retry later, and report it if it persists",
            Self::Aborted { insertion_attempted: false, .. } => "the login was not filled and no values were sent to the page; take a fresh snapshot before retrying",
            Self::Aborted { insertion_attempted: true, .. } => "the login could not be completely filled; the page remains protected because some values may have reached it; reload or navigate the page itself before retrying",
            Self::FilledPasswordOnPage => "take a snapshot to read this page instead; screenshots are refused until you reload or navigate the page itself",
            Self::WindowExpired => "reload or navigate the page itself before reading it again",
            Self::ApprovalNotGiven { decision: "declined", .. } => "the person did not approve using this saved login; call fill_login again only if they change their mind",
            Self::ApprovalNotGiven { .. } => "the approval to use this saved login did not complete; call fill_login again when the person is available",
            Self::ApprovalServiceRefused(_) => "the dedicated vault approval could not be filed; update Cingulate or report the refusal before retrying",
        }
    }

    pub(super) fn detail(self) -> Value {
        match self {
            Self::Origin { field, reason_code } => json!({
                "field": field,
                "reason_code": reason_code,
            }),
            Self::LoginUnavailable => json!({"reason_code": "login_unavailable"}),
            Self::VaultUnavailable => json!({"reason_code": "vault_unavailable"}),
            Self::Aborted { reason_code, .. } => json!({"reason_code": reason_code}),
            Self::FilledPasswordOnPage => json!({
                "reason_code": "filled_password_on_page",
                "reason": "a filled password is on this page",
            }),
            Self::WindowExpired => json!({
                "reason_code": "filled_login_expired",
                "reason": "a filled password has been on this page for ten minutes",
            }),
            Self::ApprovalNotGiven { decision, .. } => json!({
                "reason_code": "login_approval_not_given",
                "decision": decision,
            }),
            Self::ApprovalServiceRefused(reason) => match reason {
                crate::cingulate_client::desk::SecretUseRefusal::MissingCapability => {
                    json!({"reason_code": "secret_use_approval_unsupported", "reason": "Cingulate does not advertise secret-use-approval/v1"})
                }
                crate::cingulate_client::desk::SecretUseRefusal::InvalidRequest => {
                    json!({"reason_code": "elicitation_invalid_request"})
                }
                crate::cingulate_client::desk::SecretUseRefusal::RequestConflict => {
                    json!({"reason_code": "elicitation_request_conflict"})
                }
                crate::cingulate_client::desk::SecretUseRefusal::RequesterRefused => {
                    json!({"reason_code": "elicitation_requester_refused"})
                }
            },
        }
    }
}

// ---------------------------------------------------------------------------
// The window after a fill
// ---------------------------------------------------------------------------

/// A tab's state after a login was filled into it.
///
/// Empty or removed fields do not prove that page-script copies disappeared.
/// Only main-frame document replacement or context/tab/session closure ends
/// protection: subframe navigation cannot erase copies in other frames.
/// At the cap the redaction material is wiped and the window becomes a
/// quarantine: all reads refuse until document replacement.
pub(super) struct FillWindow {
    /// The main-frame document the login was filled into.
    document: CommittedDocument,
    fields: Vec<FilledField>,
    /// Emptied, and so wiped, when the window ends or its time runs out.
    password: Arc<RedactionMaterial>,
    filled_at: Instant,
    cap: Duration,
}

type RedactionMaterial = StdMutex<Option<Vec<Zeroizing<String>>>>;

impl fmt::Debug for FillWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FillWindow")
            .field("document", &self.document)
            .field("fields", &self.fields)
            .field("filled_at", &self.filled_at)
            .finish_non_exhaustive()
    }
}

impl FillWindow {
    fn open(
        document: CommittedDocument,
        fields: Vec<FilledField>,
        password: Vec<Zeroizing<String>>,
        cap: Duration,
    ) -> Self {
        let password = Arc::new(StdMutex::new(Some(password)));
        // Wipe all released material when the time runs out even if nothing reads the
        // tab again. The task holds only a weak handle, so a window that
        // ended earlier is not kept alive by it.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let slot = Arc::downgrade(&password);
            runtime.spawn(async move {
                tokio::time::sleep(cap).await;
                if let Some(slot) = slot.upgrade() {
                    take_password(&slot);
                }
            });
        }
        Self {
            document,
            fields,
            password,
            filled_at: Instant::now(),
            cap,
        }
    }

    fn timed_out(&self) -> bool {
        self.filled_at.elapsed() >= self.cap
    }

    pub(super) fn main_document_replaced(&self, live: &CommittedDocument) -> bool {
        self.document.loader_id != live.loader_id
    }

    fn extend(
        &mut self,
        fields: Vec<FilledField>,
        secrets: Vec<Zeroizing<String>>,
    ) -> Result<(), BrowserError> {
        let mut guard = self
            .password
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.timed_out() || guard.is_none() {
            return Err(BrowserError::FillRefused(FillRefusal::WindowExpired));
        }
        self.fields.extend(fields);
        guard
            .as_mut()
            .expect("checked redaction material")
            .extend(secrets);
        Ok(())
    }

    fn checkpoint(&self) -> (usize, usize) {
        let guard = self
            .password
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (self.fields.len(), guard.as_ref().map_or(0, Vec::len))
    }

    /// Remove only material staged for a dispatch that sent no values. An
    /// earlier fill's protection and expiry must survive a refused retry.
    fn restore(&mut self, (fields, secrets): (usize, usize)) {
        self.fields.truncate(fields);
        if let Some(material) = self
            .password
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
        {
            material.truncate(secrets);
        }
    }

    /// Hold the material lock through redaction, so expiry cannot wipe it
    /// between checking the cap and sanitizing the retained/output bytes.
    pub(super) fn with_redactor<T>(
        &self,
        use_redactor: impl FnOnce(&dyn Fn(&mut String)) -> T,
    ) -> Result<T, BrowserError> {
        let guard = self
            .password
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.timed_out() || guard.is_none() {
            return Err(BrowserError::FillRefused(FillRefusal::WindowExpired));
        }
        let result = use_redactor(&|text| {
            for secret in guard
                .as_ref()
                .expect("checked redaction material")
                .iter()
                .filter(|secret| !secret.is_empty())
            {
                redact_string(text, secret);
            }
        });
        if self.timed_out() {
            return Err(BrowserError::FillRefused(FillRefusal::WindowExpired));
        }
        Ok(result)
    }

    fn redact(&self, value: &mut Value) -> Result<(), BrowserError> {
        self.with_redactor(|redact| redact_json(value, redact))
    }
}

impl Drop for FillWindow {
    fn drop(&mut self) {
        take_password(&self.password);
    }
}

fn take_password(slot: &RedactionMaterial) {
    drop(
        slot.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take(),
    );
}

/// What a password is replaced with in text leaving this module.
pub const REDACTED_PASSWORD: &str = "[filled password]";

#[cfg(test)]
fn redact_value(value: &mut Value, password: &str) {
    redact_json(value, &|text| redact_string(text, password));
}

fn redact_string(text: &mut String, secret: &str) {
    if secret.is_empty() {
        return;
    }
    // Decode one HTML entity layer only for matching, retaining the original
    // byte ranges so unrelated markup stays byte-identical. Numeric and named
    // spellings (and mixed raw/encoded copies) share the same comparison.
    let mut decoded = Zeroizing::new(String::new());
    let mut ranges = Vec::new();
    let mut at = 0;
    while at < text.len() {
        let rest = &text[at..];
        let entity = rest.strip_prefix('&').and_then(|rest| {
            let end = rest.find(';').filter(|end| *end <= 12)?;
            let name = &rest[..end];
            let ch = match name {
                "amp" => '&',
                "lt" => '<',
                "gt" => '>',
                "quot" => '"',
                "apos" => '\'',
                _ => {
                    let number = name.strip_prefix('#')?;
                    let code = match number
                        .strip_prefix('x')
                        .or_else(|| number.strip_prefix('X'))
                    {
                        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                        None => number.parse().ok()?,
                    };
                    char::from_u32(code)?
                }
            };
            Some((ch, end + 2))
        });
        let (ch, length) = entity.unwrap_or_else(|| {
            let ch = rest.chars().next().expect("nonempty remainder");
            (ch, ch.len_utf8())
        });
        ranges.push((decoded.len(), at, at + length));
        decoded.push(ch);
        at += length;
    }
    let mut matches: Vec<_> = text
        .match_indices(secret)
        .map(|(start, _)| start..start + secret.len())
        .collect();
    matches.extend(decoded.match_indices(secret).filter_map(|(start, _)| {
        let first = ranges.binary_search_by_key(&start, |range| range.0).ok()?;
        let end = start + secret.len();
        let last = ranges
            .partition_point(|range| range.0 < end)
            .checked_sub(1)?;
        Some(ranges[first].1..ranges[last].2)
    }));
    // Literal entity syntax can itself be part of a password. Search the raw
    // text too, merging overlaps with the decoded matches before replacing.
    matches.sort_by_key(|range| (range.start, range.end));
    let mut merged: Vec<std::ops::Range<usize>> = Vec::new();
    for range in matches {
        if let Some(previous) = merged
            .last_mut()
            .filter(|previous| previous.end >= range.start)
        {
            previous.end = previous.end.max(range.end);
        } else {
            merged.push(range);
        }
    }
    let matches = merged;
    if !matches.is_empty() {
        // The retained allocation never contains the removed bytes, even in
        // spare capacity left behind by an in-place replacement.
        let mut redacted = String::with_capacity(text.len());
        let mut cursor = 0;
        for range in matches {
            redacted.push_str(&text[cursor..range.start]);
            redacted.push_str(REDACTED_PASSWORD);
            cursor = range.end;
        }
        redacted.push_str(&text[cursor..]);
        let mut old = std::mem::replace(text, redacted);
        old.zeroize();
    }
}

fn redact_json(value: &mut Value, redact: &dyn Fn(&mut String)) {
    match value {
        Value::String(text) => redact(text),
        Value::Array(items) => items.iter_mut().for_each(|item| redact_json(item, redact)),
        Value::Object(fields) => {
            for field in fields.values_mut() {
                redact_json(field, redact);
            }
        }
        _ => {}
    }
}

/// Which kind of read is asking to pass a tab's window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WindowRead {
    Text,
    Screenshot,
}

/// Withhold the value of every filled field from a captured observation,
/// by node identity, whatever the field's type is now.
pub(super) fn mask_filled_fields(
    observation: &mut crate::browser::navigation::BrowserSnapshotObservation,
    filled: &[BackendNodeIdentity],
) {
    let mut protected = std::collections::HashSet::new();
    for reference in &observation.refs {
        if !reference
            .backend_identity
            .as_ref()
            .is_some_and(|identity| filled.contains(identity))
        {
            continue;
        }
        let name = reference.captured.reference.clone();
        protected.insert(name.clone());
        // The page text prints a field's value only for a field known not
        // to hold a credential.
        observation
            .facts
            .entry(name.clone())
            .or_default()
            .credential = Some(true);
        for record in &mut observation.records {
            if record.reference.as_deref() == Some(name.as_str()) {
                record.value = None;
                record.name.clear();
            }
        }
    }
    let mut protected_depth = None;
    observation.records.retain(|record| {
        if protected_depth.is_some_and(|depth| record.depth <= depth) {
            protected_depth = None;
        }
        if record
            .reference
            .as_ref()
            .is_some_and(|reference| protected.contains(reference))
        {
            protected_depth = Some(record.depth);
        } else if protected_depth.is_some()
            && matches!(record.role.as_str(), "StaticText" | "InlineTextBox")
        {
            return false;
        }
        true
    });
    for reference in &mut observation.refs {
        if protected.contains(&reference.captured.reference) {
            reference.captured.name.clear();
            reference.raw_name = None;
        }
    }
}

impl BrowserPlane {
    /// Install where `browser.fill_login` gets login material; `None` leaves
    /// the capability unserved.
    pub fn with_login_material_source(
        mut self,
        source: Option<Arc<dyn LoginMaterialSource>>,
    ) -> Self {
        self.login_material = source;
        self
    }

    /// Shorten the window after a fill, for tests that cannot wait ten
    /// minutes.
    #[doc(hidden)]
    pub fn with_fill_window_for_test(mut self, cap: Duration) -> Self {
        self.fill_window_cap = cap;
        self
    }

    pub(crate) fn login_material_source(&self) -> Option<Arc<dyn LoginMaterialSource>> {
        self.login_material.clone()
    }

    /// Whether this tab is in a fill window, for tests.
    #[doc(hidden)]
    pub async fn fill_window_open_for_test(&self, identity: &RouteIdentity) -> bool {
        self.state
            .lock()
            .await
            .contexts
            .get(&identity.conversation_key)
            .is_some_and(|context| context.fill_window.is_some())
    }

    /// Decide whether a read of the tab may go ahead while it is in a fill
    /// window, and which fields to mask if it does. `live` is the document
    /// the read authorized against.
    pub(super) async fn fill_window_gate(
        &self,
        identity: &RouteIdentity,
        operation: crate::browser_session::OperationGuard,
        live: &CommittedDocument,
        deadline_ms: u64,
        read: WindowRead,
    ) -> Result<
        (
            crate::browser_session::OperationGuard,
            Option<Vec<BackendNodeIdentity>>,
        ),
        BrowserError,
    > {
        let key = identity.conversation_key.clone();
        {
            let mut state = self.state.lock().await;
            let Some(context) = state.contexts.get_mut(&key) else {
                return Err(BrowserError::NoSession);
            };
            if context.ended {
                return Err(BrowserError::NoSession);
            }
            let Some(window) = context.fill_window.as_ref() else {
                return Ok((operation, None));
            };
            if window.main_document_replaced(live) {
                context.fill_window = None;
                return Ok((operation, None));
            }
        }
        let route = key.clone();
        let (operation, frames) = tokio::task::spawn_blocking(move || {
            let mut operation = operation;
            let frames = operation.frame_documents(&route, deadline_ms);
            (operation, frames)
        })
        .await
        .map_err(|_| BrowserError::Internal {
            reason_code: JournalReasonCode::InternalFailure,
        })?;
        let mut state = self.state.lock().await;
        let context = state
            .contexts
            .get_mut(&key)
            .filter(|context| !context.ended)
            .ok_or(BrowserError::NoSession)?;
        let Some(window) = context.fill_window.as_mut() else {
            return Ok((operation, None));
        };
        // FrameDocument comparison includes loader, session, origin and parent.
        // A successful frame-tree read lets us detect subframe replacement or removal;
        // a failed transport proves neither and leaves every field protected.
        if let Ok(frames) = frames {
            window.fields.retain(|field| {
                field
                    .frame
                    .as_ref()
                    .is_none_or(|expected| frames.iter().any(|live| live.same_document(expected)))
            });
            // Only node identities expire here. Script copies can outlive a
            // subframe in its parent, so the tab's redaction and cap remain.
        }
        window.with_redactor(|_| ())?;
        if read == WindowRead::Screenshot {
            return Err(BrowserError::FillRefused(FillRefusal::FilledPasswordOnPage));
        }
        Ok((
            operation,
            Some(
                window
                    .fields
                    .iter()
                    .map(|field| field.identity.clone())
                    .collect(),
            ),
        ))
    }

    /// Remove every released login value from a reply leaving this module for a tab
    /// in a fill window.
    pub(super) async fn redact_filled_password(
        &self,
        identity: &RouteIdentity,
        reply: &mut Value,
    ) -> Result<(), BrowserError> {
        let state = self.state.lock().await;
        if let Some(window) = state
            .contexts
            .get(&identity.conversation_key)
            .and_then(|context| context.fill_window.as_ref())
        {
            window.redact(reply)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Planning and filling
// ---------------------------------------------------------------------------

/// A fill whose fields were checked against the snapshot, before any login
/// material exists.
#[derive(Debug)]
pub(crate) struct FillPlan {
    /// The saved login's name, as the agent gave it.
    pub(crate) secret: String,
    /// The one https origin of every field's frame.
    pub(crate) origin: String,
    document: CommittedDocument,
    fields: Vec<PlannedField>,
}

#[derive(Debug)]
struct PlannedField {
    field: LoginField,
    identity: BackendNodeIdentity,
    classification: NonTypeClassificationRecord,
    frame: Option<FrameDocument>,
}

fn has_token(classification: &NonTypeClassificationRecord, token: &str) -> bool {
    classification
        .target_autocomplete_tokens
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(token))
}

/// Whether the snapshot's classification makes this the kind of field the
/// argument names. `Err` is the refusal's reason code.
fn check_field_kind(
    field: LoginField,
    classification: &NonTypeClassificationRecord,
) -> Result<(), &'static str> {
    let input = classification.target_kind == TargetKind::Input;
    let input_type = classification.effective_input_type.as_deref();
    match field {
        LoginField::Password if input && input_type == Some("password") => Ok(()),
        LoginField::Password => Err("not_a_password_field"),
        // The same predicate `browser.type` refuses on: a username field is
        // never itself a credential field, and a password field never a
        // username field.
        LoginField::Username
            if input
                && !classification.is_credential_field()
                && !search_or_hidden(classification)
                && matches!(input_type, None | Some("text") | Some("email"))
                && (input_type == Some("email")
                    || has_token(classification, "username")
                    || has_token(classification, "email")) =>
        {
            Ok(())
        }
        LoginField::Username => Err("not_a_username_field"),
        LoginField::Otp if input && has_token(classification, "one-time-code") => Ok(()),
        LoginField::Otp => Err("not_a_one_time_code_field"),
    }
}

fn search_or_hidden(classification: &NonTypeClassificationRecord) -> bool {
    classification.login_field.as_ref().is_some_and(|facts| {
        facts.hidden
            || facts.role.split_ascii_whitespace().any(|role| {
                role.eq_ignore_ascii_case("search") || role.eq_ignore_ascii_case("searchbox")
            })
    })
}

fn username_like(value: &str) -> bool {
    value.split_ascii_whitespace().any(|part| {
        part.eq_ignore_ascii_case("e-mail")
            || part.eq_ignore_ascii_case("user_id")
            || part.split(['_', '-', '.']).any(|token| {
                [
                    "username", "user", "login", "email", "mail", "userid", "account",
                ]
                .iter()
                .any(|hint| token.eq_ignore_ascii_case(hint))
            })
    })
}

pub(super) fn username_uses_form_heuristic(username: &NonTypeClassificationRecord) -> bool {
    check_field_kind(LoginField::Username, username).is_err()
}

pub(super) fn check_username_field(
    username: &NonTypeClassificationRecord,
    password: &NonTypeClassificationRecord,
) -> Result<(), &'static str> {
    if !username_uses_form_heuristic(username) {
        return Ok(());
    }
    let refused = Err("not_a_username_field");
    if username.target_kind != TargetKind::Input
        || username.is_credential_field()
        || search_or_hidden(username)
        || !matches!(
            username.effective_input_type.as_deref(),
            None | Some("text") | Some("email")
        )
        || username.form_owner.is_none()
        || username.form_owner != password.form_owner
    {
        return refused;
    }
    let (Some(user), Some(pass)) = (&username.login_field, &password.login_field) else {
        return refused;
    };
    let (Some(user_order), Some(pass_order)) = (user.document_order, pass.document_order) else {
        return refused;
    };
    if user_order >= pass_order {
        return refused;
    }
    if username_like(&user.name)
        || username_like(&user.id)
        || username
            .target_autocomplete_tokens
            .iter()
            .any(|token| username_like(token))
        || (pass.preceding_text_inputs == 1
            && user
                .form_start_order
                .is_some_and(|start| start < user_order))
    {
        Ok(())
    } else {
        refused
    }
}

/// The https origin of the frame holding a field. `frame` is the field's
/// frame document, `None` for a field in the main frame, whose document is
/// `document`. `Err` is the refusal's reason code.
pub(super) fn field_origin(
    frame: Option<&FrameDocument>,
    document: &CommittedDocument,
) -> Result<String, &'static str> {
    if crate::classification::canonical_grant_origin(&document.security_origin).is_none() {
        return Err("origin_opaque");
    }
    let url = frame.map_or(document.url.as_str(), |frame| frame.url.as_str());
    match url
        .split_once(':')
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
        .as_deref()
    {
        Some("https") => {}
        Some("http") => return Err("origin_not_https"),
        // about:srcdoc, about:blank, data:, blob: and the like borrow or lack
        // an origin; none of them is a site the login was saved for.
        _ => return Err("origin_opaque"),
    }
    let origin = crate::classification::canonical_origin_from_url(url).ok_or("origin_opaque")?;
    {
        // A sandboxed document keeps its https URL but has an opaque origin.
        let actual_origin = frame.map_or(document.security_origin.as_str(), |frame| &frame.origin);
        if crate::classification::canonical_grant_origin(actual_origin).as_deref()
            != Some(origin.as_str())
        {
            return Err("origin_opaque");
        }
    }
    Ok(origin)
}

fn required_ref<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, BrowserError> {
    let reference = required_string(object, field, 2, 21)?;
    if !snapshot_store::valid_ref(reference) {
        return Err(BrowserError::InvalidRequest {
            field: field.into(),
            reason_code: "unsupported_value",
        });
    }
    Ok(reference)
}

impl BrowserPlane {
    /// Resolve and check a fill's fields in the snapshot they were shown in.
    /// Runs before the vault is asked, so a refusal here never holds a secret.
    pub(crate) async fn plan_fill_login(
        &self,
        identity: &RouteIdentity,
        args: &Value,
    ) -> Result<FillPlan, BrowserError> {
        let object = self
            .validate_request(
                args,
                &[
                    "secret",
                    "username_ref",
                    "password_ref",
                    "otp_ref",
                    "snapshot_id",
                ],
            )
            .await?;
        let secret = required_string(object, "secret", 1, 256)?.to_owned();
        let mut wanted = vec![
            (LoginField::Username, required_ref(object, "username_ref")?),
            (LoginField::Password, required_ref(object, "password_ref")?),
        ];
        if object.contains_key("otp_ref") {
            wanted.push((LoginField::Otp, required_ref(object, "otp_ref")?));
        }
        // As for browser.type: a named snapshot only chooses which elements
        // the refs name. Every check before insertion runs the same either way.
        let requested_snapshot = match object.get("snapshot_id") {
            Some(_) => {
                let id = required_string(object, "snapshot_id", 32, 32)?;
                if !snapshot_store::valid_snapshot_id(id) {
                    return Err(BrowserError::InvalidRequest {
                        field: "snapshot_id".into(),
                        reason_code: "unsupported_value",
                    });
                }
                Some(id.to_owned())
            }
            None => None,
        };
        for (index, (field, reference)) in wanted.iter().enumerate() {
            if wanted[..index]
                .iter()
                .any(|(_, earlier)| earlier == reference)
            {
                return Err(BrowserError::InvalidRequest {
                    field: field.argument().into(),
                    reason_code: "duplicate_ref",
                });
            }
        }
        let _lane = self.lane(&identity.conversation_key).await;
        let mut state = self.state.lock().await;
        let context = state
            .contexts
            .get_mut(&identity.conversation_key)
            .filter(|context| !context.ended)
            .ok_or(BrowserError::NoSession)?;
        let password_ref = wanted[1].1;
        let snapshot_id = match requested_snapshot {
            Some(id) => id,
            None => context
                .refs
                .shown(password_ref)
                .map(|shown| shown.snapshot_id.clone())
                .ok_or(BrowserError::StaleSnapshot {
                    reason_code: "not_retained",
                })?,
        };
        let snapshot = context
            .snapshots
            .pin_text(&snapshot_id, context.epoch.value())
            .map_err(map_snapshot_error)?;
        context.snapshots.unpin(&snapshot_id);
        let document = snapshot
            .source_document
            .clone()
            .ok_or(BrowserError::StaleSnapshot {
                reason_code: "snapshot_document_unknown",
            })?;
        let mut fields = Vec::new();
        for (field, reference) in wanted {
            let record = snapshot
                .refs
                .iter()
                .find(|record| record.captured.reference == reference)
                .ok_or_else(|| BrowserError::RefNotFound {
                    reference: reference.into(),
                })?;
            let classification = record
                .classification
                .as_ref()
                .map_err(|reason| BrowserError::ClassificationUnavailable(reason.clone()))?
                .as_ref()
                .clone();
            if field != LoginField::Username {
                check_field_kind(field, &classification).map_err(|reason_code| {
                    BrowserError::InvalidRequest {
                        field: field.argument().into(),
                        reason_code,
                    }
                })?;
            }
            fields.push(PlannedField {
                field,
                identity: record
                    .backend_identity
                    .clone()
                    .ok_or(BrowserError::ElementIntercepted)?,
                classification,
                frame: record.frame_document.clone(),
            });
        }
        check_username_field(&fields[0].classification, &fields[1].classification).map_err(
            |reason_code| BrowserError::InvalidRequest {
                field: LoginField::Username.argument().into(),
                reason_code,
            },
        )?;
        let password_form = &fields[1].classification.form_owner;
        if password_form.is_none() || fields[0].classification.form_owner != *password_form {
            return Err(BrowserError::InvalidRequest {
                field: LoginField::Username.argument().into(),
                reason_code: "not_in_the_password_form",
            });
        }
        // Each field's own frame decides, not the tab's URL: login forms
        // often sit in an iframe of another site.
        let mut origin: Option<String> = None;
        for planned in &fields {
            let refused = |reason_code| {
                BrowserError::FillRefused(FillRefusal::Origin {
                    field: planned.field.argument(),
                    reason_code,
                })
            };
            let this = field_origin(planned.frame.as_ref(), &document).map_err(refused)?;
            match &origin {
                Some(first) if *first != this => return Err(refused("origins_differ")),
                Some(_) => {}
                None => origin = Some(this),
            }
        }
        Ok(FillPlan {
            secret,
            origin: origin.expect("a fill has at least two fields"),
            document,
            fields,
        })
    }

    /// Run every value-independent live check before asking the vault. The
    /// empty values stand in for the planned fields; check_fill_login checks
    /// them but never inserts a value.
    pub(crate) async fn check_planned_login(
        &self,
        identity: &RouteIdentity,
        plan: &FillPlan,
    ) -> Result<(), BrowserError> {
        let _lane = self.lane(&identity.conversation_key).await;
        {
            let state = self.state.lock().await;
            let context = state
                .contexts
                .get(&identity.conversation_key)
                .filter(|context| !context.ended)
                .ok_or(BrowserError::NoSession)?;
            if let Some(window) = &context.fill_window {
                window.with_redactor(|_| ())?;
            }
        }
        let (sessions, clock, deadline_ms) =
            self.session_gate.as_ref().ok_or(BrowserError::NoSession)?;
        if let Some(handoff) = sessions.human_in_control(&identity.conversation_key, clock.as_ref())
        {
            return Err(BrowserError::HumanInControl {
                origin: handoff.origin,
                expires_in_ms: handoff.expires_in_ms,
            });
        }
        let deadline_ms = *deadline_ms;
        let operation = self
            .admit_operation(identity, BrowserCapability::Type)?
            .ok_or(BrowserError::NoSession)?;
        let dispatch = FillDispatch::new(
            plan.document.clone(),
            plan.fields
                .iter()
                .map(|field| FillTarget {
                    field: field.field,
                    identity: field.identity.clone(),
                    classification: field.classification.clone(),
                    frame: field.frame.clone(),
                    value: Zeroizing::new(String::new()),
                })
                .collect(),
        );
        let route = identity.conversation_key.clone();
        let (operation, result) = tokio::task::spawn_blocking(move || {
            let mut operation = operation;
            let result = operation.check_fill_login(&route, &dispatch, deadline_ms);
            (operation, result)
        })
        .await
        .map_err(|_| BrowserError::Internal {
            reason_code: JournalReasonCode::InternalFailure,
        })?;
        operation.finish();
        match result.map_err(map_navigation_drive_error)? {
            None => Ok(()),
            Some(reason_code) => Err(BrowserError::FillRefused(FillRefusal::Aborted {
                reason_code,
                insertion_attempted: false,
            })),
        }
    }

    /// Check the fields again on the live page and insert the login. The
    /// material is consumed: every buffer holding it is wiped when this
    /// returns, except the material kept for the tab's fill window redaction.
    pub(crate) async fn fill_planned_login(
        &self,
        identity: &RouteIdentity,
        plan: FillPlan,
        mut material: LoginMaterial,
    ) -> Result<Value, BrowserError> {
        let _lane = self.lane(&identity.conversation_key).await;
        {
            let state = self.state.lock().await;
            let context = state
                .contexts
                .get(&identity.conversation_key)
                .filter(|context| !context.ended)
                .ok_or(BrowserError::NoSession)?;
            if let Some(window) = &context.fill_window {
                window.with_redactor(|_| ())?;
            }
        }
        if let Some((sessions, clock, _)) = &self.session_gate {
            if let Some(handoff) =
                sessions.human_in_control(&identity.conversation_key, clock.as_ref())
            {
                return Err(BrowserError::HumanInControl {
                    origin: handoff.origin,
                    expires_in_ms: handoff.expires_in_ms,
                });
            }
        }
        let FillPlan {
            origin,
            document,
            fields,
            ..
        } = plan;
        let mut targets = Vec::new();
        for planned in fields {
            let value = match planned.field {
                LoginField::Username => Zeroizing::new(std::mem::take(&mut *material.username)),
                LoginField::Password => Zeroizing::new((*material.password).clone()),
                LoginField::Otp => match material.totp.as_mut() {
                    Some(code) => Zeroizing::new(std::mem::take(&mut **code)),
                    None => {
                        return Err(BrowserError::InvalidRequest {
                            field: LoginField::Otp.argument().into(),
                            reason_code: "login_has_no_one_time_code",
                        })
                    }
                },
            };
            targets.push(FillTarget {
                field: planned.field,
                identity: planned.identity,
                classification: planned.classification,
                frame: planned.frame,
                value,
            });
        }
        let secrets = targets.iter().map(|target| target.value.clone()).collect();
        drop(material);
        let filled: Vec<FilledField> = targets
            .iter()
            .map(|target| FilledField {
                identity: target.identity.clone(),
                frame: target.frame.clone(),
            })
            .collect();
        let names: Vec<&'static str> = targets.iter().map(|target| target.field.name()).collect();
        let deadline_ms = self
            .session_gate
            .as_ref()
            .map(|(_, _, deadline)| *deadline)
            .ok_or(BrowserError::NoSession)?;
        let operation = self
            .admit_operation(identity, BrowserCapability::Type)?
            .ok_or(BrowserError::NoSession)?;
        let checkpoint = {
            let mut state = self.state.lock().await;
            let context = state
                .contexts
                .get_mut(&identity.conversation_key)
                .filter(|context| !context.ended)
                .ok_or(BrowserError::NoSession)?;
            let checkpoint = context.fill_window.as_ref().map(FillWindow::checkpoint);
            match context.fill_window.as_mut() {
                Some(window) => window.extend(filled.clone(), secrets)?,
                None => {
                    context.fill_window = Some(FillWindow::open(
                        document.clone(),
                        filled.clone(),
                        secrets,
                        self.fill_window_cap,
                    ))
                }
            }
            checkpoint
        };
        // Commit before the value-bearing dispatch. The earlier precheck only
        // reads the page and cannot insert a credential.
        identity.witness.mark_committed();
        let route = identity.conversation_key.clone();
        let expected = document.clone();
        let cleared = filled.clone();
        let dispatch = FillDispatch::new(document, targets);
        let insertion_attempted = dispatch.insertion_attempted.clone();
        let dispatched = tokio::task::spawn_blocking(move || {
            let mut operation = operation;
            let outcome = operation.fill_login(&route, &dispatch, deadline_ms);
            // The values are wiped before anything else is asked of the page.
            drop(dispatch);
            let result = match outcome {
                Ok(FillOutcome::Filled) => {
                    match operation.committed_document(&route, deadline_ms) {
                        Ok(live) if live.loader_id == expected.loader_id => {
                            Ok((FillOutcome::Filled, live))
                        }
                        _ => {
                            let _ = operation.clear_filled(&route, &cleared, 1_000);
                            Ok((
                                FillOutcome::Aborted {
                                    reason_code: "document_changed",
                                },
                                expected,
                            ))
                        }
                    }
                }
                Ok(aborted) => Ok((aborted, expected)),
                Err(error) => Err(error),
            };
            (operation, result)
        })
        .await;
        let insertion_attempted = insertion_attempted.load(Ordering::Acquire);
        if !insertion_attempted {
            let mut state = self.state.lock().await;
            if let Some(context) = state.contexts.get_mut(&identity.conversation_key) {
                if let Some(checkpoint) = checkpoint {
                    if let Some(window) = &mut context.fill_window {
                        window.restore(checkpoint);
                    }
                } else {
                    context.fill_window = None;
                }
            }
        }
        let (operation, result) = dispatched.map_err(|_| BrowserError::Internal {
            reason_code: JournalReasonCode::InternalFailure,
        })?;
        operation.finish();
        match result.map_err(map_navigation_drive_error)? {
            (FillOutcome::Filled, _) => {
                Ok(json!({"outcome": "ok", "origin": origin, "filled": names}))
            }
            (FillOutcome::Aborted { reason_code }, _) => {
                Err(BrowserError::FillRefused(FillRefusal::Aborted {
                    reason_code,
                    insertion_attempted,
                }))
            }
        }
    }

    /// The finished reply for a fill's result, with its context.
    pub(crate) async fn fill_reply(
        &self,
        identity: &RouteIdentity,
        result: Result<Value, BrowserError>,
    ) -> Value {
        self.result(identity, result).await
    }

    /// Certify a fill's reply against its result schema before it reaches
    /// the module wire, as [`BrowserPlane::finish_reply`] does for the
    /// advertised capabilities.
    pub(crate) fn finish_fill_reply(
        &self,
        reply: Value,
    ) -> Result<Value, CapabilityResultValidationError> {
        match validate_fill_login_result(&reply) {
            Ok(()) => Ok(reply),
            Err(error) => {
                let mut findings = self
                    .result_schema_findings
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                *findings.entry(error.clone()).or_default() += 1;
                drop(findings);
                match self.result_schema_enforcement {
                    crate::computer_capability::ResultSchemaEnforcement::DetectOnly => Ok(reply),
                    crate::computer_capability::ResultSchemaEnforcement::Withhold => Err(error),
                }
            }
        }
    }
}

/// The replies `browser.fill_login` gives: a fill, a refusal, a pending
/// approval, or the bounded-call replies every capability can give. Kept
/// here rather than among the advertised tool definitions, which this
/// capability is not part of yet.
fn fill_login_result_schema() -> Value {
    let mut outcomes = browser_result_outcome_schema();
    outcomes["enum"]
        .as_array_mut()
        .expect("the outcome schema is an enum")
        .push(json!("cancelled"));
    json!({"anyOf": [
        closed_object(
            json!({
                "outcome": enum_schema(&["ok"]),
                "origin": string_schema(),
                "filled": string_array_schema(),
                "context": context_result_schema(),
            }),
            &["outcome", "origin", "filled", "context"],
        ),
        closed_object(
            json!({
                "outcome": outcomes,
                "remedy": string_schema(),
                "context": context_result_schema(),
                "detail": refusal_detail_schema(),
                "ask_id": string_schema(),
                "stage": string_schema(),
                "origin": string_schema(),
                "expires_in_ms": integer_schema(),
            }),
            &["outcome"],
        ),
        bounded_call_reply_schema(),
    ]})
}

pub fn validate_fill_login_result(result: &Value) -> Result<(), CapabilityResultValidationError> {
    static SCHEMA: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    let schema = SCHEMA.get_or_init(fill_login_result_schema);
    let mut violations: Vec<CapabilityResultViolation> = Vec::new();
    collect_result_violations(schema, result, "$", &mut violations);
    violations.sort();
    if violations.is_empty() {
        Ok(())
    } else {
        Err(CapabilityResultValidationError::ReplyViolations {
            capability_id: FILL_LOGIN.to_string(),
            violations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classification::{
        classify_click, ElementClassificationInput, NodeIdentityInput, NonTypeClassificationInput,
    };
    use crate::snapshot_store::{AxRecord, SnapshotKind};

    fn answer(value: Value) -> SecretUseAnswer {
        SecretUseAnswer::from_wire(Zeroizing::new(
            serde_json::to_vec(&json!({"result": value})).unwrap(),
        ))
    }

    fn field(
        build: impl FnOnce(ElementClassificationInput) -> ElementClassificationInput,
    ) -> NonTypeClassificationRecord {
        let target = build(ElementClassificationInput::new(
            NodeIdentityInput::new("target", "frame", 7),
            TargetKind::Input,
        ));
        classify_click(&NonTypeClassificationInput::new(
            1,
            target,
            "https://login.example",
        ))
        .unwrap()
    }

    fn document(url: &str) -> CommittedDocument {
        CommittedDocument {
            network: Default::default(),
            security_origin: crate::classification::canonical_origin_from_url(url)
                .unwrap_or_else(|| "null".into()),
            url: url.into(),
            entry_id: 1,
            history: vec![1],
            current_index: 0,
            loader_id: "loader".into(),
        }
    }

    fn frame(url: &str, origin: &str) -> FrameDocument {
        FrameDocument {
            network: Default::default(),
            navigation_revision: 0,
            frame_id: "child".into(),
            parent_id: Some("main".into()),
            session_id: "session".into(),
            loader_id: "child-loader".into(),
            url: url.into(),
            origin: origin.into(),
        }
    }

    #[test]
    fn the_request_is_exactly_the_vaults_closed_shape() {
        let request = SecretUseRequest {
            name: "work".into(),
            stamp: json!({"scope_ref": "sc_head"}),
            origin: "https://login.example".into(),
        };
        assert_eq!(
            request.params(),
            json!({
                "name": "work",
                "coverage": "scope",
                "stamp": {"scope_ref": "sc_head"},
                "target": {"origin": "https://login.example"},
            })
        );
    }

    fn assert_login_origin_sent_to_vault(url: &str, expected: &str) {
        let mut main = document(url);
        // Keep the browser-reported origin independent of the helper under test.
        main.security_origin = expected.into();
        let top = document("https://top.example/signin");
        let child = frame(url, expected);
        for origin in [field_origin(None, &main), field_origin(Some(&child), &top)] {
            let request = SecretUseRequest {
                name: "work".into(),
                stamp: json!({"scope_ref": "sc_head"}),
                origin: origin.unwrap(),
            };
            assert_eq!(request.origin.as_bytes(), expected.as_bytes(), "{url}");
            let encoded = crate::login_capture::secret_use::encode_params(&request);
            let wire: Value = serde_json::from_slice(&encoded).unwrap();
            for params in [request.params(), wire] {
                assert_eq!(
                    params["target"]["origin"].as_str().unwrap().as_bytes(),
                    expected.as_bytes(),
                    "{url}"
                );
            }
        }
    }

    #[test]
    fn fill_login_multi_host_fixtures_are_byte_pinned() {
        use sha2::{Digest, Sha256};

        for (bytes, expected) in [
            (
                include_bytes!(
                    "../../tests/vectors/secret-multi-host-v1/upstream-login-cases.json"
                )
                .as_slice(),
                "9bc6bee78eeea6ae004b021682967871dc8ef261e3daa7b8d3d38d164bcf54b3",
            ),
            (
                include_bytes!(
                    "../../tests/vectors/secret-multi-host-v1/derived-origin-cases.json"
                )
                .as_slice(),
                "aaf173d271308ac9adb69ca792d983bf68954c5da91d388c39d3ffc0f20c4312",
            ),
        ] {
            assert_eq!(format!("{:x}", Sha256::digest(bytes)), expected);
        }
    }

    #[test]
    fn fill_login_targets_preserve_the_vault_multi_host_vector_origins() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../tests/vectors/secret-multi-host-v1/upstream-login-cases.json"
        ))
        .unwrap();
        let mut targets = 0;
        for case in vectors["cases"].as_array().unwrap() {
            let Some(target) = case.get("target") else {
                // Scope refusals are vault verdicts, not browser URL refusals.
                continue;
            };
            targets += 1;
            let url = target["origin"].as_str().unwrap();
            let expected = match case["case"].as_str().unwrap() {
                "login-target-is-not-api-key" => "https://a.x.test",
                "four-origins" => "https://login3.x.test",
                "stored-origins-as-sent" | "legacy-login-https://x.test:443" => "https://x.test",
                "legacy-login-https://y.test" => "https://y.test",
                // Never collapse a non-default port into an origin the vault would match.
                "legacy-login-https://x.test:444" => "https://x.test:444",
                "legacy-login-http://x.test" => {
                    assert_eq!(field_origin(None, &document(url)), Err("origin_not_https"));
                    continue;
                }
                name => panic!("unaccounted login target: {name}"),
            };
            assert_login_origin_sent_to_vault(url, expected);
        }
        assert_eq!(targets, 7);
    }

    #[test]
    fn fill_login_targets_follow_the_derived_multi_host_origin_examples() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../tests/vectors/secret-multi-host-v1/derived-origin-cases.json"
        ))
        .unwrap();
        let cases = vectors["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 7);
        for case in cases {
            assert_login_origin_sent_to_vault(
                case["input"].as_str().unwrap(),
                case["canonical_origin"].as_str().unwrap(),
            );
        }
    }

    #[test]
    fn released_approval_and_refused_answers_read_as_the_vault_sends_them() {
        let SecretUseAnswer::Released(material) = answer(json!({
            "status": "released", "kind": "site_login",
            "username": "u", "password": "p", "totp": "123456",
        })) else {
            panic!("a released login");
        };
        assert_eq!(
            (
                material.username.as_str(),
                material.password.as_str(),
                material.totp.as_deref().map(String::as_str)
            ),
            ("u", "p", Some("123456"))
        );
        assert!(!format!("{material:?}").contains("123456"));
        let SecretUseAnswer::Released(without) = answer(json!({
            "status": "released", "kind": "site_login", "username": "u", "password": "p",
        })) else {
            panic!("a released login without a code");
        };
        assert!(without.totp.is_none());
        let SecretUseAnswer::ApprovalRequired(approval) = answer(json!({
            "status": "approval_required", "request_id": "req_1",
            "statement_b64url": "c3Q", "expires_at_ms": 9,
        })) else {
            panic!("an approval request");
        };
        assert_eq!(
            approval,
            Approval {
                request_id: "req_1".into(),
                statement_b64url: "c3Q".into(),
                expires_at_ms: 9
            }
        );
        for refused in [
            json!({"error": {"code": "not_found", "class": "refused"}}),
            json!({"error": {"code": "not_granted", "class": "refused"}}),
            json!({"status": "released", "kind": "api_key", "username": "u", "password": "p"}),
            json!({"status": "released", "kind": "site_login", "password": "p"}),
            json!({"status": "released", "kind": "site_login", "username": "u", "password": "p", "totp": 1}),
            json!({"status": "approval_required", "request_id": "req_1"}),
            json!({"status": "something_else"}),
        ] {
            assert!(
                matches!(answer(refused.clone()), SecretUseAnswer::Refused),
                "{refused}"
            );
        }
    }

    #[test]
    fn field_kinds_follow_the_typing_refusals_classification() {
        let password = field(|f| f.input_type("password").password(true));
        let email = field(|f| f.input_type("email"));
        let username = field(|f| f.input_type("text").autocomplete(["username"]));
        let plain = field(|f| f.input_type("text"));
        let code = field(|f| f.input_type("text").autocomplete(["one-time-code"]));
        assert_eq!(check_field_kind(LoginField::Password, &password), Ok(()));
        assert_eq!(
            check_field_kind(LoginField::Password, &username),
            Err("not_a_password_field")
        );
        assert_eq!(check_field_kind(LoginField::Username, &email), Ok(()));
        assert_eq!(check_field_kind(LoginField::Username, &username), Ok(()));
        assert_eq!(
            check_field_kind(LoginField::Username, &plain),
            Err("not_a_username_field")
        );
        assert_eq!(
            check_field_kind(LoginField::Username, &password),
            Err("not_a_username_field")
        );
        assert_eq!(check_field_kind(LoginField::Otp, &code), Ok(()));
        assert_eq!(
            check_field_kind(LoginField::Otp, &plain),
            Err("not_a_one_time_code_field")
        );
    }

    #[test]
    fn login_metadata_is_not_part_of_stored_classifications_or_fingerprints() {
        let mut classification = field(|f| f.input_type("text"));
        let bytes = classification.canonical_bytes().unwrap();
        let fingerprint = classification.try_fingerprint().unwrap();
        classification.login_field = Some(crate::classification::LoginFieldFacts {
            name: "username".into(),
            id: "id_username".into(),
            role: String::new(),
            hidden: false,
            document_order: Some(3),
            form_start_order: Some(1),
            preceding_text_inputs: 0,
        });
        assert_eq!(classification.canonical_bytes().unwrap(), bytes);
        assert_eq!(classification.try_fingerprint().unwrap(), fingerprint);
        let restored: NonTypeClassificationRecord = serde_json::from_slice(&bytes).unwrap();
        assert!(restored.login_field.is_none());
        assert_eq!(classification, restored);
    }

    #[test]
    fn a_fields_origin_is_its_own_frames_and_must_be_https() {
        let page = document("https://login.example/signin");
        assert_eq!(
            field_origin(None, &page).as_deref(),
            Ok("https://login.example")
        );
        assert_eq!(
            field_origin(
                Some(&frame(
                    "https://auth.other.example/x",
                    "https://auth.other.example"
                )),
                &page
            )
            .as_deref(),
            Ok("https://auth.other.example")
        );
        assert_eq!(
            field_origin(None, &document("http://login.example/")),
            Err("origin_not_https")
        );
        for (url, origin) in [
            ("https://auth.other.example/x", "null"),
            ("about:srcdoc", "https://login.example"),
            ("data:text/html,x", "null"),
            ("blob:https://login.example/1", "https://login.example"),
        ] {
            assert_eq!(
                field_origin(Some(&frame(url, origin)), &page),
                Err("origin_opaque"),
                "{url}"
            );
        }
    }

    #[test]
    fn redaction_replaces_every_copy_in_every_string() {
        let mut value = json!({
            "state_text": "a pw1 b pw1",
            "nested": [{"name": "pw1"}, 3, "clean"],
        });
        redact_value(&mut value, "pw1");
        assert_eq!(
            value,
            json!({
                "state_text": format!("a {REDACTED_PASSWORD} b {REDACTED_PASSWORD}"),
                "nested": [{"name": REDACTED_PASSWORD}, 3, "clean"],
            })
        );
    }

    #[test]
    fn literal_entity_spellings_in_a_secret_are_redacted_raw_and_encoded() {
        let mut value = json!(["P&amp;Q", "P&amp;amp;Q", "P&#38;amp;Q"]);
        redact_value(&mut value, "P&amp;Q");
        assert_eq!(
            value,
            json!([REDACTED_PASSWORD, REDACTED_PASSWORD, REDACTED_PASSWORD])
        );
    }

    fn protected_field(node: u64) -> FilledField {
        FilledField {
            identity: BackendNodeIdentity::new("target", "frame", node).unwrap(),
            frame: None,
        }
    }

    #[test]
    fn cumulative_windows_keep_all_nodes_and_cannot_replace_expired_quarantine() {
        let mut window = FillWindow::open(
            document("https://login.example"),
            vec![protected_field(1)],
            vec![Zeroizing::new("first-secret".into())],
            Duration::from_secs(60),
        );
        window
            .extend(
                vec![protected_field(2)],
                vec![Zeroizing::new("second-secret".into())],
            )
            .unwrap();
        assert_eq!(window.fields, vec![protected_field(1), protected_field(2)]);
        let mut reply = json!(["first-secret", "second-secret"]);
        window.redact(&mut reply).unwrap();
        assert_eq!(reply, json!([REDACTED_PASSWORD, REDACTED_PASSWORD]));
        window.filled_at = Instant::now() - Duration::from_secs(61);
        assert!(window
            .extend(
                vec![protected_field(3)],
                vec![Zeroizing::new("third".into())]
            )
            .is_err());
        assert_eq!(window.fields.len(), 2);
    }

    #[test]
    fn wiped_redaction_material_refuses_instead_of_returning_plaintext() {
        let window = FillWindow::open(
            document("https://login.example"),
            vec![protected_field(1)],
            vec![Zeroizing::new("secret".into())],
            Duration::from_secs(60),
        );
        take_password(&window.password);
        let mut reply = json!({"state_text":"secret"});
        assert!(matches!(
            window.redact(&mut reply),
            Err(BrowserError::FillRefused(FillRefusal::WindowExpired))
        ));
    }

    fn route() -> RouteIdentity {
        RouteIdentity::from_bind(
            &subc_protocol::BindIdentity::new("test", "fill-hardening"),
            &Some(subc_protocol::Principal::Direct),
        )
    }

    #[tokio::test]
    async fn retained_snapshots_and_pinned_ref_names_are_already_redacted() {
        let plane = BrowserPlane::new();
        let identity = route();
        plane.open_context(identity.clone()).await.unwrap();
        {
            let mut state = plane.state.lock().await;
            state
                .contexts
                .get_mut(&identity.conversation_key)
                .unwrap()
                .fill_window = Some(FillWindow::open(
                document("https://login.example"),
                vec![protected_field(1)],
                vec![Zeroizing::new("retained-secret".into())],
                Duration::from_secs(60),
            ));
        }
        let records = vec![AxRecord {
            depth: 0,
            role: "button".into(),
            name: "retained-secret".into(),
            value: None,
            reference: Some("e1".into()),
        }];
        let refs = vec![crate::snapshot_store::RefRecord {
            captured: crate::snapshot_store::SnapshotRef::new("e1", "button", "retained-secret", 0)
                .unwrap(),
            backend_identity: None,
            frame_document: None,
            frame_path: vec![],
            raw_role: None,
            raw_name: Some("retained-secret".into()),
            classification: Err(crate::classification::ClassificationUnavailable::NotCaptured),
        }];
        let reply = plane
            .retain_text_snapshot(
                &identity,
                SnapshotKind::Ax,
                &records,
                None,
                refs,
                4096,
                Some(document("https://login.example")),
            )
            .await
            .unwrap();
        let mut state = plane.state.lock().await;
        let context = state.contexts.get_mut(&identity.conversation_key).unwrap();
        let id = reply["snapshot_id"].as_str().unwrap();
        let pinned = context
            .snapshots
            .pin_text(id, context.epoch.value())
            .unwrap();
        assert!(!pinned.content.contains("retained-secret"));
        assert!(pinned.content.contains(REDACTED_PASSWORD));
        assert_eq!(pinned.refs[0].captured.name, REDACTED_PASSWORD);
        assert_eq!(pinned.refs[0].raw_name.as_deref(), Some(REDACTED_PASSWORD));
        context.snapshots.unpin(id);
    }

    #[tokio::test]
    async fn an_ended_context_refuses_before_consuming_planned_material() {
        let plane = BrowserPlane::new();
        let identity = route();
        plane.open_context(identity.clone()).await.unwrap();
        plane.end_context(&identity, false).await;
        let plan = FillPlan {
            secret: "login".into(),
            origin: "https://login.example".into(),
            document: document("https://login.example"),
            fields: vec![PlannedField {
                field: LoginField::Otp,
                identity: protected_field(1).identity,
                classification: field(|f| f.input_type("text").autocomplete(["one-time-code"])),
                frame: None,
            }],
        };
        let result = plane
            .fill_planned_login(
                &identity,
                plan,
                LoginMaterial {
                    username: Zeroizing::new("username".into()),
                    password: Zeroizing::new("password".into()),
                    totp: None,
                },
            )
            .await;
        assert!(matches!(result, Err(BrowserError::NoSession)), "{result:?}");
        assert!(!plane.fill_window_open_for_test(&identity).await);
    }

    #[test]
    fn identity_mask_clears_ax_names_values_and_inner_text_for_any_role() {
        let identity = BackendNodeIdentity::new("target", "frame", 1).unwrap();
        let mut observation = crate::browser::navigation::BrowserSnapshotObservation {
            records: vec![
                AxRecord {
                    depth: 0,
                    role: "region".into(),
                    name: "new page value".into(),
                    value: Some("new page value".into()),
                    reference: Some("e1".into()),
                },
                AxRecord {
                    depth: 1,
                    role: "StaticText".into(),
                    name: "new page value".into(),
                    value: None,
                    reference: None,
                },
                AxRecord {
                    depth: 0,
                    role: "StaticText".into(),
                    name: "unrelated".into(),
                    value: None,
                    reference: None,
                },
            ],
            dom_text: None,
            refs: vec![crate::snapshot_store::RefRecord {
                captured: crate::snapshot_store::SnapshotRef::new(
                    "e1",
                    "region",
                    "new page value",
                    0,
                )
                .unwrap(),
                backend_identity: Some(identity.clone()),
                frame_document: None,
                frame_path: vec![],
                raw_role: None,
                raw_name: Some("new page value".into()),
                classification: Err(crate::classification::ClassificationUnavailable::NotCaptured),
            }],
            facts: Default::default(),
            ax_truncated: false,
            refs_truncated: false,
        };
        mask_filled_fields(&mut observation, &[identity]);
        assert_eq!(observation.records.len(), 2);
        assert!(observation.records[0].name.is_empty());
        assert!(observation.records[0].value.is_none());
        assert_eq!(observation.records[1].name, "unrelated");
        assert!(observation.refs[0].captured.name.is_empty());
    }

    /// Agents call the fill through the flat `browser_use` tool, so a fill
    /// remedy names its flat actions (snapshot, fill_login) and never a
    /// granular capability such as `browser.snapshot`.
    #[test]
    fn fill_remedies_name_flat_actions() {
        let refusals = [
            FillRefusal::Origin {
                field: "otp_ref",
                reason_code: "origins_differ",
            },
            FillRefusal::LoginUnavailable,
            FillRefusal::VaultUnavailable,
            FillRefusal::Aborted {
                reason_code: "document_changed",
                insertion_attempted: true,
            },
            FillRefusal::Aborted {
                reason_code: "owner_frame_changed",
                insertion_attempted: false,
            },
            FillRefusal::FilledPasswordOnPage,
            FillRefusal::WindowExpired,
            FillRefusal::ApprovalNotGiven {
                decision: "declined",
                asked: true,
            },
            FillRefusal::ApprovalNotGiven {
                decision: "timeout",
                asked: false,
            },
            FillRefusal::ApprovalServiceRefused(
                crate::cingulate_client::desk::SecretUseRefusal::MissingCapability,
            ),
        ];
        for refusal in refusals {
            assert!(
                !refusal.remedy().contains("browser."),
                "{refusal:?}: {}",
                refusal.remedy()
            );
        }
        assert!(FillRefusal::FilledPasswordOnPage
            .remedy()
            .starts_with("take a snapshot"));
        assert!(FillRefusal::ApprovalNotGiven {
            decision: "declined",
            asked: true,
        }
        .remedy()
        .contains("call fill_login again"));
    }

    #[test]
    fn every_fill_reply_is_declared_by_the_fill_schema() {
        let context = json!({
            "profile_uuid": null, "profile_name": null,
            "session_kind_effective": "primary", "profile_disposition": "durable",
        });
        let mut replies = vec![
            json!({"outcome": "ok", "origin": "https://login.example", "filled": ["username", "password"], "context": context}),
            json!({"outcome": "cancelled", "context": context}),
        ];
        let mut pending = crate::cingulate_client::desk::pending_reply("el_1");
        pending["context"] = context.clone();
        replies.push(pending);
        for refusal in [
            FillRefusal::Origin {
                field: "otp_ref",
                reason_code: "origins_differ",
            },
            FillRefusal::LoginUnavailable,
            FillRefusal::VaultUnavailable,
            FillRefusal::Aborted {
                reason_code: "document_changed",
                insertion_attempted: true,
            },
            FillRefusal::Aborted {
                reason_code: "owner_frame_changed",
                insertion_attempted: false,
            },
            FillRefusal::FilledPasswordOnPage,
            FillRefusal::WindowExpired,
            FillRefusal::ApprovalNotGiven {
                decision: "declined",
                asked: true,
            },
        ] {
            replies.push(json!({
                "outcome": refusal.outcome(),
                "remedy": refusal.remedy(),
                "detail": refusal.detail(),
                "context": context,
            }));
        }
        for reply in replies {
            assert_eq!(validate_fill_login_result(&reply), Ok(()), "{reply}");
        }
        assert!(validate_fill_login_result(&json!({"outcome": "ok", "password": "x"})).is_err());
    }

    /// The switch is on, and it admits `browser.fill_login` only together
    /// with a source: the real one a running module's plane is given. A
    /// plane built for tests has none, so it still does not serve the fill.
    #[test]
    fn production_switch_admits_only_with_the_real_source_installed() {
        const { assert!(FILL_LOGIN_ENABLED) };
        let source = production_login_material_source(
            PathBuf::from("unread-connection-file"),
            "cerebellum".into(),
        );
        assert!(source.enabled());
        let plane = BrowserPlane::new().with_login_material_source(Some(source));
        assert!(plane.login_material.is_some());
        assert_eq!(admitted(FILL_LOGIN, &plane, true), Some(FILL_LOGIN));
        // Without a configured browser there is nothing to fill into.
        assert_eq!(admitted(FILL_LOGIN, &plane, false), None);

        let test_plane = BrowserPlane::new();
        assert!(test_plane.login_material_source().is_none());
        assert_eq!(admitted(FILL_LOGIN, &test_plane, true), None);
        let planes =
            crate::isolated_test_planes(&Arc::new(cerebellum_core::health::HealthState::new()));
        assert!(planes.browser.login_material_source().is_none());
        assert_eq!(admitted(FILL_LOGIN, &planes.browser, true), None);
    }
}
