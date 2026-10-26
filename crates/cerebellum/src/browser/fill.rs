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
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex, Weak};
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

/// Where production gets login material from. While this is `None`,
/// `browser.fill_login` is refused in production as `capability_not_admitted`:
/// no plane built for a running module has a source, and only a plane that
/// has one serves the capability. Tests install a source of their own with
/// [`BrowserPlane::with_login_material_source`].
///
/// Setting it to the vault's source enables the capability. Before that:
/// - the browser journal needs a `browser.fill_login` capability, minted as a
///   new journal format revision, recording the outcome, the origin and the
///   names of the filled fields, never their values. Until then a fill writes
///   no journal entry;
/// - the card registry needs a rollback check: approval cards of kind
///   `secret_use` are written to the stored registry, so it must be confirmed
///   that the previous release reads a registry holding a kind it does not
///   know. While this is `None` no such card can be written.
pub const PRODUCTION_LOGIN_MATERIAL_SOURCE: Option<fn() -> Arc<dyn LoginMaterialSource>> = None;

/// The source a plane built for a running module is given.
pub fn production_login_material_source() -> Option<Arc<dyn LoginMaterialSource>> {
    PRODUCTION_LOGIN_MATERIAL_SOURCE.map(|make| make())
}

/// `name`, when it is `browser.fill_login` and this plane serves it.
pub fn admitted<'a>(
    name: &'a str,
    plane: &BrowserPlane,
    browser_configured: bool,
) -> Option<&'a str> {
    (name == FILL_LOGIN && browser_configured && plane.login_material.is_some()).then_some(name)
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
    Pin<Box<dyn Future<Output = Result<Value, SourceUnavailable>> + Send + 'a>>;

/// Where login material comes from: the vault's `secret.use`.
///
/// The reply is the vault's answer as it arrived. [`SecretUseAnswer::from_reply`]
/// moves the secret strings out of it into zeroizing buffers and wipes what
/// is left, so the source should hand over the reply and keep no copy.
pub trait LoginMaterialSource: Send + Sync {
    fn secret_use(&self, request: &SecretUseRequest) -> SourceFuture<'_>;
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
    /// Read the vault's reply, taking its secret strings into zeroizing
    /// buffers and wiping every string left in it before it is dropped.
    pub fn from_reply(mut reply: Value) -> Self {
        let answer = Self::read(&mut reply);
        wipe(&mut reply);
        answer
    }

    fn read(reply: &mut Value) -> Self {
        if reply.get("error").is_some() {
            return Self::Refused;
        }
        match reply.get("status").and_then(Value::as_str) {
            Some("released") if reply.get("kind").and_then(Value::as_str) == Some("site_login") => {
                let (Some(username), Some(password)) = (
                    take_string(reply, "username"),
                    take_string(reply, "password"),
                ) else {
                    return Self::Refused;
                };
                let totp = match reply.get("totp") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(_)) => take_string(reply, "totp"),
                    Some(_) => return Self::Refused,
                };
                Self::Released(LoginMaterial {
                    username,
                    password,
                    totp,
                })
            }
            Some("approval_required") => {
                let text = |key: &str| reply.get(key).and_then(Value::as_str).map(str::to_owned);
                match (
                    text("request_id"),
                    text("statement_b64url"),
                    reply.get("expires_at_ms").and_then(Value::as_u64),
                ) {
                    (Some(request_id), Some(statement_b64url), Some(expires_at_ms))
                        if !request_id.is_empty() && !statement_b64url.is_empty() =>
                    {
                        Self::ApprovalRequired(Approval {
                            request_id,
                            statement_b64url,
                            expires_at_ms,
                        })
                    }
                    _ => Self::Refused,
                }
            }
            _ => Self::Refused,
        }
    }
}

fn take_string(reply: &mut Value, key: &str) -> Option<Zeroizing<String>> {
    match reply.get_mut(key) {
        Some(Value::String(value)) => Some(Zeroizing::new(std::mem::take(value))),
        _ => None,
    }
}

/// Zero every string in `value`, so a reply dropped after its secrets were
/// taken (or never taken, for a reply this module refused) leaves nothing.
fn wipe(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe),
        Value::Object(fields) => fields.values_mut().for_each(wipe),
        _ => {}
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
#[derive(Debug)]
pub struct FillDispatch {
    /// The main-frame document the snapshot was taken from.
    pub document: Option<CommittedDocument>,
    /// In insertion order.
    pub targets: Vec<FillTarget>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FillOutcome {
    Filled,
    /// Nothing is left in any field: the fill stopped before inserting, or
    /// cleared what it had inserted.
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
    /// The page changed between the checks and the insertion; nothing was
    /// left in any field.
    Aborted { reason_code: &'static str },
    /// A screenshot of a tab holding a filled password.
    FilledPasswordOnPage,
    /// A read of a tab whose filled login has outlived its window.
    WindowExpired,
    /// The person's approval for using the login did not arrive. `asked`
    /// is false when the question could not be put to anyone.
    ApprovalNotGiven { decision: &'static str, asked: bool },
}

impl FillRefusal {
    pub(super) fn outcome(self) -> &'static str {
        match self {
            Self::VaultUnavailable => "internal_error",
            Self::Aborted { .. } => "stale_snapshot",
            Self::ApprovalNotGiven { asked: false, .. } => "consent_unavailable",
            Self::Origin { .. }
            | Self::LoginUnavailable
            | Self::FilledPasswordOnPage
            | Self::WindowExpired
            | Self::ApprovalNotGiven { asked: true, .. } => "authorization_denied",
        }
    }

    pub(super) fn remedy(self) -> &'static str {
        match self {
            Self::Origin { .. } => "a saved login goes only into fields whose frames are https and share one origin; choose the fields of such a form from a fresh browser.snapshot",
            Self::LoginUnavailable => "this agent cannot use a saved login of that name on this site; check the name with the person, or ask them to share the login with this agent for this site",
            Self::VaultUnavailable => "the vault could not be reached; retry later, and report it if it persists",
            Self::Aborted { .. } => "the page changed before the login went in, and nothing was left in its fields; take a fresh browser.snapshot and call browser.fill_login again",
            Self::FilledPasswordOnPage => "read this page with browser.snapshot instead; screenshots of it are refused until it navigates to another document or its filled fields are emptied",
            Self::WindowExpired => "navigate this tab to another page, or submit its form, before reading it again",
            Self::ApprovalNotGiven { decision: "declined", .. } => "the person did not approve using this saved login; call browser.fill_login again only if they change their mind",
            Self::ApprovalNotGiven { .. } => "the approval to use this saved login did not complete; call browser.fill_login again when the person is available",
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
            Self::Aborted { reason_code } => json!({"reason_code": reason_code}),
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
        }
    }
}

// ---------------------------------------------------------------------------
// The window after a fill
// ---------------------------------------------------------------------------

/// A tab's state after a login was filled into it.
///
/// The window lasts until the page commits another document, every filled
/// field is empty or removed, the tab or its session closes, or
/// [`FILL_WINDOW`] passes. While it lasts, screenshots of the tab are refused,
/// and text read from it has the filled fields masked and every copy of the
/// password removed; the password is kept, zeroizing, for that removal only.
/// When the time runs out the password is wiped, and reads of the tab are
/// refused until it navigates.
pub(super) struct FillWindow {
    /// The main-frame document the login was filled into.
    document: CommittedDocument,
    fields: Vec<FilledField>,
    /// Emptied, and so wiped, when the window ends or its time runs out.
    password: Arc<StdMutex<Option<Zeroizing<String>>>>,
    filled_at: Instant,
    cap: Duration,
}

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
        password: Zeroizing<String>,
        cap: Duration,
    ) -> Self {
        let password = Arc::new(StdMutex::new(Some(password)));
        // Wipe the password when the time runs out even if nothing reads the
        // tab again. The task holds only a weak handle, so a window that
        // ended earlier is not kept alive by it.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let slot: Weak<StdMutex<Option<Zeroizing<String>>>> = Arc::downgrade(&password);
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

    /// Remove every exact copy of the password from the strings in `value`.
    fn redact(&self, value: &mut Value) {
        let guard = self
            .password
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(password) = guard.as_ref().filter(|password| !password.is_empty()) {
            redact_value(value, password);
        }
    }
}

impl Drop for FillWindow {
    fn drop(&mut self) {
        take_password(&self.password);
    }
}

fn take_password(slot: &StdMutex<Option<Zeroizing<String>>>) {
    drop(
        slot.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take(),
    );
}

/// What a password is replaced with in text leaving this module.
pub const REDACTED_PASSWORD: &str = "[filled password]";

fn redact_value(value: &mut Value, password: &str) {
    match value {
        Value::String(text) if text.contains(password) => {
            let mut redacted = text.replace(password, REDACTED_PASSWORD);
            std::mem::swap(text, &mut redacted);
            redacted.zeroize();
        }
        Value::Array(items) => items
            .iter_mut()
            .for_each(|item| redact_value(item, password)),
        Value::Object(fields) => {
            for field in fields.values_mut() {
                redact_value(field, password);
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
    for reference in &observation.refs {
        if !reference
            .backend_identity
            .as_ref()
            .is_some_and(|identity| filled.contains(identity))
        {
            continue;
        }
        let name = reference.captured.reference.clone();
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
            }
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
        let fields = {
            let mut state = self.state.lock().await;
            let Some(context) = state.contexts.get_mut(&key) else {
                return Ok((operation, None));
            };
            let Some(window) = context.fill_window.as_ref() else {
                return Ok((operation, None));
            };
            if window.document.loader_id != live.loader_id {
                // Another document: the filled form is gone with the old one.
                context.fill_window = None;
                return Ok((operation, None));
            }
            if window.timed_out() {
                take_password(&window.password);
                return Err(BrowserError::FillRefused(FillRefusal::WindowExpired));
            }
            window.fields.clone()
        };
        let route = key.clone();
        let checked = fields.clone();
        let (operation, filled) = tokio::task::spawn_blocking(move || {
            let mut operation = operation;
            let filled = operation.filled_fields_state(&route, &checked, deadline_ms);
            (operation, filled)
        })
        .await
        .map_err(|_| BrowserError::Internal {
            reason_code: JournalReasonCode::InternalFailure,
        })?;
        // A field whose state could not be read counts as still filled.
        if matches!(filled, Ok(FilledFieldsState::AllEmptyOrGone)) {
            let mut state = self.state.lock().await;
            if let Some(context) = state.contexts.get_mut(&key) {
                context.fill_window = None;
            }
            return Ok((operation, None));
        }
        if read == WindowRead::Screenshot {
            return Err(BrowserError::FillRefused(FillRefusal::FilledPasswordOnPage));
        }
        Ok((
            operation,
            Some(fields.into_iter().map(|field| field.identity).collect()),
        ))
    }

    /// Remove the filled password from a reply leaving this module for a tab
    /// in a fill window.
    pub(super) async fn redact_filled_password(&self, identity: &RouteIdentity, reply: &mut Value) {
        let state = self.state.lock().await;
        if let Some(window) = state
            .contexts
            .get(&identity.conversation_key)
            .and_then(|context| context.fill_window.as_ref())
        {
            window.redact(reply);
        }
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

/// The https origin of the frame holding a field. `frame` is the field's
/// frame document, `None` for a field in the main frame, whose document is
/// `document`. `Err` is the refusal's reason code.
fn field_origin(
    frame: Option<&FrameDocument>,
    document: &CommittedDocument,
) -> Result<String, &'static str> {
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
    if let Some(frame) = frame {
        // A sandboxed frame keeps its https URL but has an opaque origin.
        if crate::classification::canonical_grant_origin(&frame.origin).as_deref()
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
            .validate_request(args, &["secret", "username_ref", "password_ref", "otp_ref"])
            .await?;
        let secret = required_string(object, "secret", 1, 256)?.to_owned();
        let mut wanted = vec![
            (LoginField::Username, required_ref(object, "username_ref")?),
            (LoginField::Password, required_ref(object, "password_ref")?),
        ];
        if object.contains_key("otp_ref") {
            wanted.push((LoginField::Otp, required_ref(object, "otp_ref")?));
        }
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
        let snapshot_id = context
            .refs
            .shown(password_ref)
            .map(|shown| shown.snapshot_id.clone())
            .ok_or(BrowserError::StaleSnapshot {
                reason_code: "not_retained",
            })?;
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
            check_field_kind(field, &classification).map_err(|reason_code| {
                BrowserError::InvalidRequest {
                    field: field.argument().into(),
                    reason_code,
                }
            })?;
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

    /// Check the fields again on the live page and insert the login. The
    /// material is consumed: every buffer holding it is wiped when this
    /// returns, except the password kept for the tab's fill window.
    pub(crate) async fn fill_planned_login(
        &self,
        identity: &RouteIdentity,
        plan: FillPlan,
        mut material: LoginMaterial,
    ) -> Result<Value, BrowserError> {
        let _lane = self.lane(&identity.conversation_key).await;
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
        let password = Zeroizing::new(std::mem::take(&mut *material.password));
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
        // The dispatch commitment, reached before the first CDP command of
        // the fill: a reply without it means nothing reached the page.
        identity.witness.mark_committed();
        let route = identity.conversation_key.clone();
        let expected = document.clone();
        let cleared = filled.clone();
        let dispatch = FillDispatch {
            document: Some(document),
            targets,
        };
        let (operation, result) = tokio::task::spawn_blocking(move || {
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
                            let _ = operation.clear_filled(&route, &cleared, deadline_ms);
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
        .await
        .map_err(|_| BrowserError::Internal {
            reason_code: JournalReasonCode::InternalFailure,
        })?;
        operation.finish();
        match result.map_err(map_navigation_drive_error)? {
            (FillOutcome::Filled, live) => {
                let mut state = self.state.lock().await;
                if let Some(context) = state.contexts.get_mut(&identity.conversation_key) {
                    context.fill_window = Some(FillWindow::open(
                        live,
                        filled,
                        password,
                        self.fill_window_cap,
                    ));
                }
                Ok(json!({"outcome": "ok", "origin": origin, "filled": names}))
            }
            (FillOutcome::Aborted { reason_code }, _) => {
                Err(BrowserError::FillRefused(FillRefusal::Aborted {
                    reason_code,
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
            url: url.into(),
            entry_id: 1,
            history: vec![1],
            current_index: 0,
            loader_id: "loader".into(),
        }
    }

    fn frame(url: &str, origin: &str) -> FrameDocument {
        FrameDocument {
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

    #[test]
    fn released_approval_and_refused_answers_read_as_the_vault_sends_them() {
        let SecretUseAnswer::Released(material) = SecretUseAnswer::from_reply(json!({
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
        let SecretUseAnswer::Released(without) = SecretUseAnswer::from_reply(json!({
            "status": "released", "kind": "site_login", "username": "u", "password": "p",
        })) else {
            panic!("a released login without a code");
        };
        assert!(without.totp.is_none());
        let SecretUseAnswer::ApprovalRequired(approval) = SecretUseAnswer::from_reply(json!({
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
                matches!(
                    SecretUseAnswer::from_reply(refused.clone()),
                    SecretUseAnswer::Refused
                ),
                "{refused}"
            );
        }
    }

    #[test]
    fn a_reply_is_wiped_once_its_secrets_are_taken() {
        let mut reply =
            json!({"status": "released", "nested": ["secret-copy", {"deep": "secret"}]});
        wipe(&mut reply);
        assert_eq!(reply, json!({"status": "", "nested": ["", {"deep": ""}]}));
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

    #[test]
    fn production_has_no_login_material_source() {
        assert!(PRODUCTION_LOGIN_MATERIAL_SOURCE.is_none());
        let plane =
            BrowserPlane::new().with_login_material_source(production_login_material_source());
        assert_eq!(admitted(FILL_LOGIN, &plane, true), None);
    }
}
