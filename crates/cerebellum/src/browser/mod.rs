//! Browser capabilities exposed by the browser plane.
//!
//! This module integrates route admission, journal and context interfaces, CDP
//! transport, and browser geometry, extraction, and screenshot primitives.
//! Browser-specific state is kept behind a per-context lane so CDP operations
//! and final verification cannot interleave across invocations.

pub mod extraction;
pub mod geometry;
pub mod navigation;
mod refs;
mod scroll;
pub mod state_text;

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant};

use cerebellum_core::journal::{
    journal_data_path, CallerRefusalHistory, RefusalRing, RefusalRingConfig,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tokio::sync::{Mutex, OwnedMutexGuard};

use crate::authorization::{AuthorizationRequest, GrantStore, HazardClass, Severity};
use crate::classification::ClassificationUnavailable;
use crate::computer_capability::ResultSchemaEnforcement;
use crate::coordinate::{
    capture_screenshot, map_pixel_to_css, validate_png_base64_dimensions, CoordinateError,
    InvalidCoordinatesReason, ScreenshotPayload, TransformInputs, ViewportObservation,
    MAX_ENCODED_PNG_BYTES,
};
use crate::journal;
use crate::journal::reservation::{
    CompletedResult, DispatchCommitmentToken, DispatchMaterial, FinalContextAssociation,
    RejectionMaterial, ReservationHandle,
};
use crate::journal::store::JournalStore;
use crate::journal::{
    Action as JournalAction, Capability as JournalCapability, GoverningObservation, GrantDecision,
    JournalError, JournalIdentity, JournalReasonCode, Outcome, SessionKind as JournalSessionKind,
};
use crate::snapshot_store::{
    self, AxRecord, BrowserSnapshotStore, CommittedDocument, DocumentEpoch, DocumentTransition,
    SameDocumentChange, SnapshotError, SnapshotKind, TextSnapshot, AX_SCHEMA, DOM_SCHEMA, MAX_REFS,
};
use cerebellum_computer::platform::vocabulary::{
    CapabilityResultValidationError, CapabilityResultViolation,
};
use cerebellum_core::identity::{ProfileDisposition, RouteIdentity, SessionKind};

pub const NAVIGATE: &str = "browser.navigate";
pub const SNAPSHOT: &str = "browser.snapshot";
pub const CLICK: &str = "browser.click";
pub const TYPE: &str = "browser.type";
pub const SCREENSHOT: &str = "browser.screenshot";
pub const SCROLL: &str = "browser.scroll";
pub const CLICK_POINT: &str = "browser.click_point";
pub const WAIT_FOR: &str = "browser.wait_for";
/// The wire refusal code shared with the computer plane for a result-schema violation.
pub const RESULT_SCHEMA_VIOLATION_CODE: &str = "computer_result_schema_violation";
pub const ALL_TOOLS: [&str; 8] = [
    NAVIGATE,
    SNAPSHOT,
    CLICK,
    TYPE,
    SCREENSHOT,
    SCROLL,
    CLICK_POINT,
    WAIT_FOR,
];

/// Whether a browser capability has a working module-wire dispatch route.
///
/// Deliberately admit only operations with working wire dispatch routes. The
/// omitted operations once returned `outcome: ok` with a fabricated `url_final`
/// even when no browser process existed.
pub fn has_wire_dispatch_route(name: &str) -> bool {
    matches!(
        name,
        NAVIGATE
            | SNAPSHOT
            | CLICK
            | TYPE
            | SCREENSHOT
            | SCROLL
            | CLICK_POINT
            | crate::management::PRESENT
            | crate::management::RESUME
    )
}

pub const SETTLEMENT_MS: u64 = 30_000;
pub const QUIET_MS: u64 = 500;
const DEFAULT_READ_PAGE_MAX_BYTES: u64 = 5_000;
const DEFAULT_REFUSAL_RECORDS_PER_CALLER: usize = 64;
const BROWSER_REFUSAL_RING_FILE: &str = "browser-refusals.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserCapability {
    Navigate,
    Snapshot,
    Click,
    Type,
    Screenshot,
    Scroll,
    ClickPoint,
    WaitFor,
}
impl BrowserCapability {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Navigate => NAVIGATE,
            Self::Snapshot => SNAPSHOT,
            Self::Click => CLICK,
            Self::Type => TYPE,
            Self::Screenshot => SCREENSHOT,
            Self::Scroll => SCROLL,
            Self::ClickPoint => CLICK_POINT,
            Self::WaitFor => WAIT_FOR,
        }
    }
    pub const fn is_unfenceable(self) -> bool {
        matches!(
            self,
            Self::Navigate | Self::Click | Self::Type | Self::ClickPoint | Self::Scroll
        )
    }
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            NAVIGATE => Self::Navigate,
            SNAPSHOT => Self::Snapshot,
            CLICK => Self::Click,
            TYPE => Self::Type,
            SCREENSHOT => Self::Screenshot,
            SCROLL => Self::Scroll,
            CLICK_POINT => Self::ClickPoint,
            WAIT_FOR => Self::WaitFor,
            _ => return None,
        })
    }
}

/// Typed authorization decisions retained by the browser refusal ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotRefusalReason {
    NoGrant,
    OriginScope,
    /// The page committed a navigation to another origin while it was being
    /// read, so the captured content was discarded unreturned.
    PageNavigatedDuringRead,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BrowserError {
    InvalidRequest {
        field: String,
        reason_code: &'static str,
    },
    NoSession,
    BrowserLaunchPending,
    HumanInControl {
        origin: String,
        expires_in_ms: u64,
    },
    StaleSnapshot {
        reason_code: &'static str,
    },
    /// The page no longer shows the document the addressed snapshot or
    /// screenshot was taken from, so its refs or pixels name nothing there.
    PageChangedSinceSnapshot {
        snapshot_origin: String,
        live_origin: String,
    },
    RefNotFound {
        reference: String,
    },
    RefAmbiguous {
        candidate_count: usize,
    },
    ElementIntercepted,
    Intercepted(Value),
    ClassificationUnavailable(ClassificationUnavailable),
    OutsideViewportAfterScroll {
        refusal: crate::browser_session::ViewportRefusal,
    },
    PointOutsideViewport {
        refusal: crate::browser_session::ViewportRefusal,
    },
    InvalidCoordinates {
        reason: InvalidCoordinatesReason,
    },
    ImageTooLarge {
        bytes: usize,
        bound_bytes: usize,
    },
    AuthorizationDenied {
        reason: &'static str,
    },
    /// Grants reach the severity but none names the attempted origin.
    /// `required` and `required_hazards` are what a grant for that origin
    /// must cover, so the reply can name the grant that admits the retry.
    AuthorizationOriginScope {
        attempted_origin: String,
        granted_origins: Vec<String>,
        required: crate::authorization::Severity,
        required_hazards: std::collections::BTreeSet<HazardClass>,
    },
    /// The conversation holds no grant. Reported as `no_grant`, with the
    /// origin and severity a grant must cover to admit this action.
    AuthorizationNoGrantForAction {
        attempted_origin: String,
        required: crate::authorization::Severity,
    },
    /// The conversation holds grants, but no ceiling reaches the severity this
    /// action needs.
    AuthorizationSeverityInsufficient {
        attempted_origin: String,
        required: crate::authorization::Severity,
        granted_ceilings: Vec<crate::authorization::Severity>,
    },
    HazardNotDisclosed {
        missing: HazardClass,
        /// Why the target had no classification, when that is what made the
        /// hazard unverified. `None` for a classified target.
        classification_unavailable: Option<ClassificationUnavailable>,
        /// The origin, severity and every hazard a grant must cover to admit
        /// this action; `missing` alone can leave another one uncovered.
        attempted_origin: String,
        required: crate::authorization::Severity,
        required_hazards: std::collections::BTreeSet<HazardClass>,
    },
    /// The requested severity is under the action's floor. `required` is the
    /// value the authorization check computed for this target.
    SeverityBelowFloor {
        required: crate::authorization::Severity,
        classification_unavailable: Option<ClassificationUnavailable>,
    },
    NavigationPolicyRejected {
        reason_code: &'static str,
    },
    NavigationFailed {
        error_text: String,
    },
    /// A page read was authorized for `authorized_origin`, and by the time the
    /// capture returned the page showed a document from `live_origin`. The
    /// captured content is withheld because no grant was consulted for it.
    PageNavigatedDuringRead {
        authorized_origin: String,
        live_origin: String,
    },
    NotSettled {
        url_final: Option<String>,
        lifecycle: Vec<String>,
        inflight_count: u64,
        deadline_ms: u64,
    },
    NavigateNotReady {
        reason_code: &'static str,
        navigation_sent: bool,
    },
    TypeNotReady {
        reason_code: &'static str,
    },
    CommandTimeout {
        step: String,
        command_sent: bool,
    },
    CdpStepFailure {
        step: String,
    },
    BrowserCrashed,
    Internal {
        reason_code: JournalReasonCode,
    },
    /// The browser session table's lock is poisoned, so whether a session
    /// exists is unknown and no browser action can be admitted.
    SessionStateUnavailable,
}

impl BrowserError {
    fn outcome(&self) -> &'static str {
        match self {
            Self::InvalidRequest { .. } | Self::SeverityBelowFloor { .. } => "invalid_request",
            Self::NoSession => "no_session",
            Self::BrowserLaunchPending => "browser_launch_pending",
            Self::HumanInControl { .. } => "human_in_control",
            Self::StaleSnapshot { .. } | Self::PageChangedSinceSnapshot { .. } => "stale_snapshot",
            Self::RefNotFound { .. } => "ref_not_found",
            Self::RefAmbiguous { .. } => "ref_ambiguous",
            Self::ClassificationUnavailable(_) => "classification_unavailable",
            Self::ElementIntercepted | Self::Intercepted(_) => "element_intercepted",
            Self::OutsideViewportAfterScroll { .. } => "outside_viewport_after_scroll",
            Self::PointOutsideViewport { .. } => "point_outside_viewport",
            Self::InvalidCoordinates { .. } => "invalid_coordinates",
            Self::ImageTooLarge { .. } => "image_too_large",
            Self::AuthorizationDenied { .. }
            | Self::AuthorizationOriginScope { .. }
            | Self::AuthorizationNoGrantForAction { .. }
            | Self::AuthorizationSeverityInsufficient { .. } => "authorization_denied",
            Self::HazardNotDisclosed { .. } => "hazard_not_disclosed",
            Self::NavigationPolicyRejected { .. } => "navigation_policy_rejected",
            Self::NavigationFailed { .. } => "navigation_failed",
            Self::PageNavigatedDuringRead { .. } => "page_navigated_during_read",
            Self::NotSettled { .. } => "not_settled",
            Self::NavigateNotReady { .. } => "navigate_not_ready",
            Self::TypeNotReady { .. } => "type_not_ready",
            Self::CommandTimeout { .. } => "command_timeout",
            Self::BrowserCrashed => "browser_crashed",
            Self::Internal { .. } | Self::CdpStepFailure { .. } => "internal_error",
            Self::SessionStateUnavailable => "internal_failure",
        }
    }
    /// Tell a caller which action can change this refusal, or explicitly when none exists.
    fn remedy(&self) -> &'static str {
        match self {
            Self::InvalidRequest { reason_code, .. } if *reason_code == "path_abandons_custody" => {
                "omit path; authenticated-session pixels stay inside this module's retention machinery"
            }
            Self::InvalidRequest { reason_code: "credential_input_unsupported", .. } => {
                "use browser_use present to hand sign-in or payment input to the person; resume afterward"
            }
            Self::NavigateNotReady { navigation_sent: false, .. } => "the setup step in detail.reason_code did not become ready before the deadline; Page.navigate was not sent; retry navigation when the browser is ready",
            Self::NavigateNotReady { navigation_sent: true, .. } => "Page.navigate was sent but its response did not arrive before the deadline; navigation may have completed; snapshot first to inspect the current page, then retry only if needed",
            Self::TypeNotReady { .. } => "the typing step in detail.reason_code was not ready; snapshot again and inspect the field before retrying, because earlier input may have reached the page",
            Self::CommandTimeout { .. } => "the CDP step in detail.step exceeded its deadline; let the page settle, then retry snapshot; inspect the page before retrying input because earlier input may have reached it",
            Self::CdpStepFailure { .. } => "the CDP step in detail.step could not supply a valid response; let the page settle, then retry snapshot; if it persists, report detail.reason_code and detail.step; do not assume earlier input completed",
            Self::InvalidRequest { .. } => {
                "correct detail.field according to detail.reason_code, then resubmit the request"
            }
            Self::SeverityBelowFloor { .. } => {
                "resubmit with detail.required as the severity; a grant must cover that severity for this target"
            }
            Self::NoSession => "call browser.launch, then retry the browser action",
            Self::BrowserLaunchPending => {
                "poll browser.status until the session is ready, then retry the browser action"
            }
            Self::HumanInControl { .. } => "browser.resume",
            Self::StaleSnapshot {
                reason_code: "ref_from_older_snapshot",
            } => {
                "this ref came from an older snapshot without browser node identity; omit zoom to read the current outline"
            }
            Self::StaleSnapshot { .. } => {
                "call browser.snapshot again and use only its new snapshot_id and refs"
            }
            Self::PageChangedSinceSnapshot { .. } => {
                "take a fresh browser.snapshot (or browser.screenshot for click_point) of the page as it is now and act on its snapshot_id; if detail.live_origin is not granted, that read needs browser.open_grant for it first"
            }
            Self::RefNotFound { .. } => {
                "choose a ref listed in the snapshot identified by snapshot_id"
            }
            Self::RefAmbiguous { .. } => {
                "take a fresh browser.snapshot and choose a ref that identifies exactly one current element"
            }
            Self::ClassificationUnavailable(crate::classification::ClassificationUnavailable::TargetNotInDocument { .. }) => "the hit node is outside the classified document; take a fresh frame-aware snapshot; if its frame remains unavailable, report the missing frame classification cause",
            Self::ClassificationUnavailable(crate::classification::ClassificationUnavailable::NotCaptured) => "take a new snapshot to capture target classification before clicking",
            Self::ClassificationUnavailable(_) => "the browser could not supply complete DOM classification; retry a fresh snapshot after the page finishes loading; if it persists, report the named classification cause",
            Self::ElementIntercepted | Self::Intercepted(_) => {
                "take a fresh browser.snapshot and choose a ref that currently exposes a clickable position"
            }
            Self::OutsideViewportAfterScroll { .. } => {
                "take a fresh browser.snapshot and choose a ref whose resolved point can enter the visual viewport"
            }
            Self::PointOutsideViewport { .. } => {
                "call browser.screenshot again and choose a point inside its current visual viewport"
            }
            Self::InvalidCoordinates { reason } => reason.remedy(),
            Self::ImageTooLarge { .. } => {
                "use browser.snapshot for a text observation, or reduce the viewport before capturing another image"
            }
            // The bare form is only produced when the grant selected for this
            // action changed before it was committed. Nothing about what a new
            // grant must cover is known here, and a retry re-runs selection,
            // whose refusal (if any) names the exact grant to open.
            Self::AuthorizationDenied { .. } => {
                "retry the browser action; if it is refused again, follow that refusal's remedy"
            }
            Self::AuthorizationNoGrantForAction {
                attempted_origin,
                required,
            }
            | Self::AuthorizationSeverityInsufficient {
                attempted_origin,
                required,
                ..
            }
            | Self::AuthorizationOriginScope {
                attempted_origin,
                required,
                ..
            }
            | Self::HazardNotDisclosed {
                attempted_origin,
                required,
                ..
            } => grant_remedy(attempted_origin, *required),
            Self::NavigationPolicyRejected { .. } => {
                "navigate to an http or https URL allowed by browser policy"
            }
            Self::NavigationFailed { .. } => {
                "inspect detail.error_text and choose a reachable destination or retry when that browser error is transient"
            }
            Self::PageNavigatedDuringRead { .. } => {
                "read the page again with browser.snapshot or browser.screenshot; if it stays on detail.live_origin, that read needs browser.open_grant for detail.live_origin first"
            }
            Self::NotSettled { .. } => {
                "call browser.snapshot to re-observe the page before depending on its current state"
            }
            Self::BrowserCrashed => {
                "no caller remedy in v1: this module does not reconnect a crashed browser"
            }
            Self::Internal { .. } => {
                "report this module failure with detail.reason_code and do not assume the action completed"
            }
            Self::SessionStateUnavailable => {
                "no caller remedy: report this module failure with its stage; the browser session state is unreadable until the module restarts"
            }
        }
    }

    fn detail(&self) -> Option<Value> {
        Some(match self {
            Self::InvalidRequest { field, reason_code }
                if *reason_code == "path_abandons_custody" =>
            {
                json!({
                    "field": field,
                    "reason_code": reason_code,
                    "reason": "writing authenticated-session pixels to a caller-chosen path abandons custody: outside the retention machinery, with no eviction and no audit of where they went",
                })
            }
            Self::InvalidRequest { field, reason_code } => {
                json!({"field":field,"reason_code":reason_code})
            }
            Self::NavigateNotReady {
                reason_code,
                navigation_sent,
            } => json!({"reason_code":reason_code,"navigation_sent":navigation_sent}),
            Self::TypeNotReady { reason_code } => json!({"reason_code":reason_code}),
            Self::CommandTimeout { step, command_sent } => {
                json!({"reason_code":"command_deadline_expired","step":step,"command_sent":command_sent})
            }
            Self::CdpStepFailure { step } => json!({"reason_code":"cdp_failure","step":step}),
            Self::StaleSnapshot { reason_code } => json!({"reason_code":reason_code}),
            Self::PageChangedSinceSnapshot {
                snapshot_origin,
                live_origin,
            } => json!({
                "reason_code":"page_changed_since_snapshot",
                "snapshot_origin":snapshot_origin,
                "live_origin":live_origin,
            }),
            Self::RefNotFound { reference } => json!({"ref":reference}),
            Self::RefAmbiguous { candidate_count } => json!({"candidates":candidate_count}),
            Self::InvalidCoordinates { reason } => {
                json!({"reason_code":reason.reason_code()})
            }
            Self::ImageTooLarge { bytes, bound_bytes } => {
                json!({"bytes":bytes,"bound_bytes":bound_bytes})
            }
            Self::AuthorizationDenied { reason } => json!({"reason":reason}),
            Self::AuthorizationOriginScope {
                attempted_origin,
                granted_origins,
                required,
                required_hazards,
            } => {
                let mut detail = grant_requirement_detail(
                    "origin_scope",
                    attempted_origin,
                    *required,
                    required_hazards,
                );
                detail["granted_origins"] = json!(granted_origins);
                detail
            }
            Self::AuthorizationNoGrantForAction {
                attempted_origin,
                required,
            } => grant_requirement_detail(
                "no_grant",
                attempted_origin,
                *required,
                &Default::default(),
            ),
            Self::AuthorizationSeverityInsufficient {
                attempted_origin,
                required,
                granted_ceilings,
            } => {
                let mut detail = grant_requirement_detail(
                    "grant_severity_insufficient",
                    attempted_origin,
                    *required,
                    &Default::default(),
                );
                detail["granted_ceilings"] = Value::Array(
                    granted_ceilings
                        .iter()
                        .copied()
                        .map(severity_value)
                        .collect(),
                );
                detail
            }
            Self::HazardNotDisclosed {
                missing,
                classification_unavailable,
                attempted_origin,
                required,
                required_hazards,
            } => {
                let mut detail = grant_requirement_detail(
                    "hazard_not_disclosed",
                    attempted_origin,
                    *required,
                    required_hazards,
                );
                detail["missing_hazard"] = json!(missing.as_str());
                with_classification_unavailable(detail, classification_unavailable.as_ref())
            }
            Self::SeverityBelowFloor {
                required,
                classification_unavailable,
            } => with_classification_unavailable(
                json!({
                    "field":"severity",
                    "reason_code":"severity_below_floor",
                    "required":{
                        "tier":required.tier,
                        "credential":required.credential,
                        "financial":required.financial,
                    },
                }),
                classification_unavailable.as_ref(),
            ),
            Self::NotSettled {
                url_final,
                lifecycle,
                inflight_count,
                deadline_ms,
            } => {
                json!({"url_final":url_final,"lifecycle":lifecycle,"inflight_count":inflight_count,"deadline_ms":deadline_ms})
            }
            Self::NavigationPolicyRejected { reason_code } => json!({"reason_code":reason_code}),
            Self::NavigationFailed { error_text } => json!({"error_text":error_text}),
            Self::PageNavigatedDuringRead {
                authorized_origin,
                live_origin,
            } => json!({
                "reason_code":"page_navigated_during_read",
                "authorized_origin":authorized_origin,
                "live_origin":live_origin,
            }),
            Self::Internal { reason_code } => json!({"reason_code":reason_code.as_str()}),
            Self::NoSession => {
                json!({"reason_code":"no_session","reason":"no browser session is open"})
            }
            Self::BrowserLaunchPending => json!({"reason_code":"browser_launch_pending"}),
            Self::HumanInControl { .. } | Self::SessionStateUnavailable => return None,
            Self::ClassificationUnavailable(reason) => {
                json!({"classification_unavailable":reason.reason_code(), "classification_unavailable_facts":reason.facts()})
            }
            Self::Intercepted(detail) => detail.clone(),
            Self::ElementIntercepted => {
                json!({"hit_role":null,"hit_name":null,"hit_inside_target":null,"reason_code":"click_position_unavailable"})
            }
            Self::OutsideViewportAfterScroll { refusal } => {
                viewport_refusal_detail("outside_viewport_after_scroll", *refusal)
            }
            Self::PointOutsideViewport { refusal } => {
                viewport_refusal_detail("point_outside_viewport", *refusal)
            }
            Self::BrowserCrashed => json!({"reason_code":"browser_crashed"}),
        })
    }
}

fn severity_value(severity: crate::authorization::Severity) -> Value {
    json!({
        "tier":severity.tier,
        "credential":severity.credential,
        "financial":severity.financial,
    })
}

/// Whether `browser.open_grant` can mint a ceiling that covers `required`.
/// Its tier input stops at `MAX_GRANTABLE_TIER`, so a caller who declared a
/// higher severity has to lower the declaration instead of asking a person.
fn grant_can_reach(required: crate::authorization::Severity) -> bool {
    required.tier <= crate::authorization::MAX_GRANTABLE_TIER
}

/// Whether a grant can name `origin` at all. Refusals carry the origin as the
/// authorization check saw it, which is the raw page origin when it has no
/// canonical form (a `file://` page, for one) and the opaque `null` on an
/// about:blank, data: or sandboxed page. `browser.open_grant` refuses any
/// origin that is not already canonical by this same function, so offering
/// either as grant arguments would send the caller to a certain refusal.
fn grant_can_name_origin(origin: &str) -> bool {
    crate::classification::canonical_grant_origin(origin).as_deref() == Some(origin)
}

/// The remedy for a refusal a new grant could cure. It must agree with
/// whether `grant_request` below produced arguments, because the remedy
/// points at them.
fn grant_remedy(attempted_origin: &str, required: crate::authorization::Severity) -> &'static str {
    if !grant_can_reach(required) {
        "no grant can be opened above tier 4; resubmit with a severity whose tier is at most 4"
    } else if !grant_can_name_origin(attempted_origin) {
        "no grant can name detail.attempted_origin; navigate to an http or https page, then retry"
    } else {
        "call browser.open_grant with the arguments in detail.grant_request, then retry"
    }
}

/// The exact `browser.open_grant` arguments whose grant admits an action at
/// `attempted_origin` that needs `required` and whose target carries
/// `target_hazards`, or `None` when no grant can (see `grant_remedy`).
///
/// Hazards: every target hazard must be disclosed, and a grant gets its
/// credential and financial flags only from disclosed hazards, so a flag the
/// target hazards do not already supply adds the hazard class that does.
/// Tier: `browser.open_grant` never mints below the tier its hazards imply
/// (at least compose even with none), so the tier named here is the one the
/// grant will actually carry, computed by the function that mints it. Naming
/// the raw required tier instead would send a caller a number the grant and
/// the person's consent question then contradict.
fn grant_request(
    attempted_origin: &str,
    required: crate::authorization::Severity,
    target_hazards: &std::collections::BTreeSet<HazardClass>,
) -> Option<Value> {
    if !grant_can_reach(required) || !grant_can_name_origin(attempted_origin) {
        return None;
    }
    let mut hazards = target_hazards.clone();
    let from_hazards = crate::management::browser_grant_minted_severity(&hazards, None);
    if required.credential && !from_hazards.credential {
        hazards.insert(HazardClass::CredentialFormSubmit);
    }
    if required.financial && !from_hazards.financial {
        hazards.insert(HazardClass::FinancialFormSubmit);
    }
    let minted = crate::management::browser_grant_minted_severity(&hazards, Some(required.tier));
    Some(json!({
        "origins":[attempted_origin],
        "severity_tier":minted.tier,
        "hazards":hazards.iter().map(|hazard| hazard.as_str()).collect::<Vec<_>>(),
    }))
}

/// Detail shared by every refusal a new grant can cure: the attempted origin,
/// the severity a grant must cover, and `grant_request` when one can be
/// opened. Each refusal adds its own facts beside these.
fn grant_requirement_detail(
    reason: &str,
    attempted_origin: &str,
    required: crate::authorization::Severity,
    target_hazards: &std::collections::BTreeSet<HazardClass>,
) -> Value {
    let mut detail = json!({
        "reason":reason,
        "attempted_origin":attempted_origin,
        "required":severity_value(required),
    });
    if let Some(request) = grant_request(attempted_origin, required, target_hazards) {
        detail["grant_request"] = request;
    }
    detail
}

/// Name the reason a click target was unclassified beside the refusal it
/// caused, so a caller can tell a page this module could not read from a form
/// it actually found.
fn with_classification_unavailable(
    mut detail: Value,
    reason: Option<&ClassificationUnavailable>,
) -> Value {
    if let (Some(reason), Some(object)) = (reason, detail.as_object_mut()) {
        object.insert(
            "classification_unavailable".into(),
            Value::from(reason.reason_code()),
        );
        object.insert(
            "classification_unavailable_facts".into(),
            Value::Object(reason.facts()),
        );
    }
    detail
}

// A loaded document is usable even if background traffic outlasts the single
// navigation deadline. Keep the quiet verdict separate from load success.
fn navigate_reply(tracker: &Tracker, should_settle: bool) -> Value {
    let loaded = tracker.url_final.is_some()
        && tracker.load_observed
        && tracker.main_frame_failure().is_none();
    let mut response = navigation_reply(tracker, false);
    response["lifecycle"] = json!({
        "events": tracker.lifecycle,
        "loaded": loaded,
        "settled": loaded && tracker.settled,
    });
    if tracker.download_blocked {
        response["outcome"] = json!("unsupported_download");
        response["remedy"] = json!(
            "the download was blocked; choose an in-page action that does not start a download"
        );
    } else if should_settle && !loaded {
        response["outcome"] = json!("not_settled");
        let pending = if tracker.url_final.is_none() {
            "main document has not committed"
        } else {
            tracker
                .main_frame_failure()
                .unwrap_or("main document load event is still pending")
        };
        response["remedy"] = json!(format!(
            "navigation deadline expired: {pending}; take a snapshot to inspect the page before retrying"
        ));
    }
    response
}

/// The reply fields a navigation reports from its tracker.
///
/// Both navigation and clicks share landing URL and HTTP metadata here.
/// Navigate wraps the lifecycle to distinguish document load from network quiet.
fn navigation_reply(tracker: &Tracker, should_settle: bool) -> Value {
    let mut response = if should_settle && !tracker.settled {
        json!({
            "outcome":"not_settled",
            "remedy":"call browser.snapshot to re-observe the page before depending on its current state",
            "url_final":tracker.url_final,
            "lifecycle":tracker.lifecycle,
        })
    } else {
        json!({"outcome":"ok","url_final":tracker.url_final,"lifecycle":tracker.lifecycle})
    };
    let response_object = response
        .as_object_mut()
        .expect("navigation response is an object");
    if let Some(status) = tracker.http_status() {
        response_object.insert("http_status".into(), json!(status));
    }
    if tracker.cloudflare_challenge() {
        response_object.insert(
            "challenge".into(),
            json!({"vendor":"cloudflare","evidence":"cf-mitigated: challenge"}),
        );
    }
    response
}

fn viewport_refusal_detail(
    reason_code: &'static str,
    refusal: crate::browser_session::ViewportRefusal,
) -> Value {
    json!({
        "reason_code": reason_code,
        "point": {
            "x_css": refusal.position.x_css,
            "y_css": refusal.position.y_css,
        },
        "viewport": {
            "x_css": refusal.viewport.x_input_css,
            "y_css": refusal.viewport.y_input_css,
            "width_css": refusal.viewport.width_input_css,
            "height_css": refusal.viewport.height_input_css,
        },
    })
}

impl fmt::Display for BrowserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.outcome())
    }
}
impl std::error::Error for BrowserError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserContextResult {
    pub profile_uuid: Option<String>,
    pub profile_name: Option<String>,
    pub session_kind_effective: &'static str,
    pub profile_disposition: &'static str,
}

impl BrowserContextResult {
    pub fn from_identity(identity: &RouteIdentity) -> Self {
        let kind = match identity.session_kind {
            SessionKind::Primary => "primary",
            SessionKind::Subagent => "subagent",
            SessionKind::Ephemeral => "ephemeral",
        };
        let profile = identity.resolve_profile();
        let disposition = match profile.profile_disposition {
            ProfileDisposition::Durable => "durable",
            ProfileDisposition::Disposable => "disposable",
            ProfileDisposition::None => "none",
        };
        Self {
            profile_uuid: None,
            profile_name: profile.profile_name,
            session_kind_effective: kind,
            profile_disposition: disposition,
        }
    }
    fn json(&self) -> Value {
        json!({"profile_uuid":self.profile_uuid,"profile_name":self.profile_name,"session_kind_effective":self.session_kind_effective,"profile_disposition":self.profile_disposition})
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainFrameResponse {
    pub status: u16,
    pub status_text: String,
    pub headers: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Tracker {
    pub download_blocked: bool,
    pub url_final: Option<String>,
    pub main_frame_response: Option<MainFrameResponse>,
    pub lifecycle: Vec<String>,
    pub inflight_count: u64,
    pub settled: bool,
    pub load_observed: bool,
    pending_requests: HashMap<String, (Instant, bool)>,
    main_frame_id: Option<String>,
    pending_document_responses: HashMap<String, MainFrameResponse>,
    quiet_since: Option<Instant>,
    /// The main frame asked to leave its current document. Set from events a
    /// renderer-initiated navigation (a link click, a form submission, script)
    /// emits before any network activity, so a click can tell that it caused a
    /// navigation before the new document commits.
    main_frame_navigation_requested: bool,
    /// The main frame changed URL without replacing its document (a fragment
    /// link, `history.pushState`). Kept apart from `url_final`, which only a
    /// committed cross-document navigation sets.
    main_frame_same_document_url: Option<String>,
    /// The main frame stopped loading. Together with no committed navigation
    /// this means the navigation ended without replacing the page, as a 204
    /// response or a download does.
    main_frame_stopped_loading: bool,
    /// Document requests by request id, so a later `Network.loadingFailed`,
    /// which carries no frame id, can be attributed to the frame it was for.
    document_request_frames: HashMap<String, String>,
    /// Failed document loads by frame id, held until main-frame identity
    /// resolves, for the same reason document responses are.
    pending_document_failures: HashMap<String, String>,
    /// Why the committed main-frame navigation failed, when the browser
    /// committed its own error page in place of the requested document.
    main_frame_failure: Option<String>,
}
impl Tracker {
    pub fn token(&mut self, token: impl Into<String>) {
        self.lifecycle.push(token.into());
    }
    pub fn request_started(&mut self) {
        self.inflight_count = self.inflight_count.saturating_add(1);
        self.quiet_since = None;
        self.settled = false;
    }
    pub fn request_finished(&mut self, now: Instant) {
        self.inflight_count = self.inflight_count.saturating_sub(1);
        if self.inflight_count == 0 {
            self.quiet_since = Some(now);
        }
    }
    // Request identity prevents redirects and late completions from corrupting
    // the count; persistent transports must not hold a loaded page hostage.
    fn network_request_started(&mut self, id: &str, kind: &str, now: Instant) {
        if !self.pending_requests.contains_key(id) {
            self.pending_requests.insert(
                id.to_string(),
                (now, matches!(kind, "WebSocket" | "EventSource")),
            );
            self.inflight_count = self.inflight_count.saturating_add(1);
        }
        self.refresh_network_quiet(now);
    }
    fn network_request_finished(&mut self, id: &str, now: Instant) {
        if self.pending_requests.remove(id).is_some() {
            self.inflight_count = self.inflight_count.saturating_sub(1);
        }
        self.refresh_network_quiet(now);
    }
    fn network_request_type(&mut self, id: &str, kind: &str, now: Instant) {
        if let Some((_, persistent)) = self.pending_requests.get_mut(id) {
            *persistent |= matches!(kind, "WebSocket" | "EventSource");
        }
        self.refresh_network_quiet(now);
    }
    fn refresh_network_quiet(&mut self, now: Instant) {
        let active = self
            .pending_requests
            .values()
            .filter(|(started, persistent)| {
                !persistent && now.saturating_duration_since(*started) < Duration::from_secs(3)
            })
            .count() as u64;
        // One outstanding short request is normal for a rendered page. Two or
        // more reset the window; requests older than three seconds are long polls.
        let anonymous = self
            .inflight_count
            .saturating_sub(self.pending_requests.len() as u64);
        if active + anonymous > 1 {
            self.quiet_since = None;
            self.settled = false;
        } else {
            self.quiet_since.get_or_insert(now);
        }
    }
    pub fn observe_main_frame_response(
        &mut self,
        frame_id: &str,
        status: u16,
        status_text: String,
        headers: Map<String, Value>,
    ) {
        let response = MainFrameResponse {
            status,
            status_text,
            headers,
        };
        match self.main_frame_id.as_deref() {
            Some(main_frame_id) if main_frame_id == frame_id => {
                self.main_frame_response = Some(response);
            }
            Some(_) => {}
            None => {
                self.pending_document_responses
                    .insert(frame_id.to_string(), response);
            }
        }
    }
    pub fn main_frame_navigated(&mut self, frame_id: Option<String>, url: String) {
        self.main_frame_response = frame_id
            .as_ref()
            .and_then(|frame_id| self.pending_document_responses.remove(frame_id));
        self.pending_document_responses.clear();
        self.pending_document_failures.clear();
        self.main_frame_id = frame_id;
        self.url_final = Some(url);
    }
    /// A committed main-frame navigation that landed on the browser's own
    /// error page. `unreachable_url` is what the browser failed to load; the
    /// reason comes from the failed document request buffered for this frame.
    pub fn main_frame_navigation_unreachable(
        &mut self,
        frame_id: Option<String>,
        url: String,
        unreachable_url: &str,
    ) {
        let failure = frame_id
            .as_ref()
            .and_then(|frame_id| self.pending_document_failures.remove(frame_id));
        self.pending_document_failures.clear();
        self.main_frame_navigated(frame_id, url);
        self.main_frame_failure =
            Some(failure.unwrap_or_else(|| format!("could not load {unreachable_url}")));
    }
    pub fn document_request_started(&mut self, request_id: &str, frame_id: &str) {
        self.document_request_frames
            .insert(request_id.to_string(), frame_id.to_string());
    }
    pub fn document_request_failed(&mut self, request_id: &str, error_text: String) {
        let Some(frame_id) = self.document_request_frames.remove(request_id) else {
            return;
        };
        match self.main_frame_id.as_deref() {
            Some(main_frame_id) if main_frame_id == frame_id => {
                self.main_frame_failure = Some(error_text);
            }
            Some(_) => {}
            None => {
                self.pending_document_failures.insert(frame_id, error_text);
            }
        }
    }
    pub fn main_frame_navigation_requested(&mut self) {
        self.main_frame_navigation_requested = true;
    }
    pub fn main_frame_navigated_within_document(&mut self, url: String) {
        self.main_frame_same_document_url = Some(url);
    }
    pub fn main_frame_stopped_loading(&mut self) {
        self.main_frame_stopped_loading = true;
    }
    /// Whether the main frame has begun, or already committed, a navigation
    /// to another document.
    pub fn main_frame_navigation_observed(&self) -> bool {
        self.download_blocked || self.main_frame_navigation_requested || self.url_final.is_some()
    }
    pub fn same_document_url(&self) -> Option<&str> {
        self.main_frame_same_document_url.as_deref()
    }
    /// The main frame began a navigation and then stopped loading without
    /// committing a new document, so the page the caller was on is still the
    /// page shown.
    pub fn navigation_ended_without_commit(&self) -> bool {
        self.main_frame_navigation_requested
            && self.main_frame_stopped_loading
            && self.url_final.is_none()
    }
    pub fn main_frame_failure(&self) -> Option<&str> {
        self.main_frame_failure.as_deref()
    }
    pub fn http_status(&self) -> Option<u16> {
        self.main_frame_response
            .as_ref()
            .map(|response| response.status)
    }
    pub fn cloudflare_challenge(&self) -> bool {
        self.main_frame_response.as_ref().is_some_and(|response| {
            response.headers.iter().any(|(name, value)| {
                name.eq_ignore_ascii_case("cf-mitigated") && value.as_str() == Some("challenge")
            })
        })
    }
    pub fn load(&mut self, now: Instant) {
        self.load_observed = true;
        self.token("load");
        if self.inflight_count == 0 {
            self.quiet_since = Some(now);
        }
    }
    pub fn poll_settlement(&mut self, now: Instant) -> bool {
        self.refresh_network_quiet(now);
        if self.load_observed
            && self
                .quiet_since
                .is_some_and(|since| now.duration_since(since) >= Duration::from_millis(QUIET_MS))
        {
            if !self.settled {
                self.token("network_quiet");
            }
            self.settled = true;
        }
        self.settled
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LateEvent {
    DownloadBlocked,
    JsDialogDismissed,
    NavigationPolicyRejected { reason_code: String },
    AuthorizationDenied { reason: String },
}
impl LateEvent {
    fn outcome(&self) -> &'static str {
        match self {
            Self::DownloadBlocked => "unsupported_download",
            Self::JsDialogDismissed => "unsupported_js_dialog",
            Self::NavigationPolicyRejected { .. } => "navigation_policy_rejected",
            Self::AuthorizationDenied { .. } => "authorization_denied",
        }
    }

    fn remedy(&self) -> &'static str {
        match self {
            Self::DownloadBlocked => "choose an in-page action that does not start a download",
            Self::JsDialogDismissed => {
                "call browser.snapshot and continue from the page state after the dialog was dismissed"
            }
            Self::NavigationPolicyRejected { .. } => {
                "navigate to an http or https URL allowed by browser policy"
            }
            Self::AuthorizationDenied { .. } => {
                "call browser.open_grant to mint a grant covering this action, then retry"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Reserve,
    FinalizeRejected,
    CommitDispatched,
    FinalizeDispatched,
    CdpObserve,
    CdpNavigate,
    CdpInputPress,
    CdpInputRelease,
    CloseContext,
}

/// One invocation-bound handle into the plane's journal store.
///
/// The reservation and commitment stay together so finalization cannot address
/// another invocation's entry. The journal store itself belongs to the plane.
struct JournalInvocation {
    browser_capability: BrowserCapability,
    capability: JournalCapability,
    handle: Option<ReservationHandle>,
    token: Option<DispatchCommitmentToken>,
    terminal: bool,
}

impl JournalInvocation {
    fn new(browser_capability: BrowserCapability) -> Self {
        Self {
            browser_capability,
            capability: journal_capability(browser_capability),
            handle: None,
            token: None,
            terminal: false,
        }
    }

    fn reserve(
        &mut self,
        store: &mut JournalStore,
        identity: JournalIdentity,
    ) -> Result<ReservationHandle, JournalError> {
        if self.terminal {
            return Err(JournalError::internal_failure());
        }
        if let Some(handle) = self.handle {
            return Ok(handle);
        }
        let handle = store.reserve(identity, self.capability)?;
        self.handle = Some(handle);
        Ok(handle)
    }

    fn commit_dispatched(
        &mut self,
        store: &mut JournalStore,
        material: DispatchMaterial,
    ) -> Result<DispatchCommitmentToken, JournalError> {
        let handle = self.handle.ok_or_else(JournalError::internal_failure)?;
        if self.terminal {
            return Err(JournalError::internal_failure());
        }
        let token = store.commit_dispatched(handle, &material)?;
        self.token = Some(token);
        Ok(token)
    }

    fn finalize_rejected(
        &mut self,
        store: &mut JournalStore,
        material: RejectionMaterial,
    ) -> Result<(), JournalError> {
        if self.terminal {
            return Err(JournalError::internal_failure());
        }
        let handle = self.handle.ok_or_else(JournalError::internal_failure)?;
        store.finalize_rejected(handle, &material).map(|_| {
            self.terminal = true;
        })
    }

    fn finalize_dispatched(
        &mut self,
        store: &mut JournalStore,
        context: FinalContextAssociation,
        result: CompletedResult,
    ) -> Result<(), JournalError> {
        if self.terminal {
            return Err(JournalError::internal_failure());
        }
        let token = self.token.ok_or_else(JournalError::internal_failure)?;
        store
            .finalize_dispatched(token, &context, &result)
            .map(|_| {
                self.terminal = true;
            })
    }
}

/// Build the journal identity projection from the immutable route identity facts
/// established during route binding.
pub fn journal_identity(identity: &RouteIdentity) -> JournalIdentity {
    JournalIdentity {
        principal: "first_party".to_string(),
        conversation_key: identity.conversation_key.clone(),
        agent_project_id: identity.agent_project_id.clone(),
        session_kind: match identity.session_kind {
            SessionKind::Primary => JournalSessionKind::Primary,
            SessionKind::Subagent => JournalSessionKind::Subagent,
            SessionKind::Ephemeral => JournalSessionKind::Ephemeral,
        },
        profile_uuid: None,
        profile_name: identity.resolve_profile().profile_name,
        origin: identity.origin.clone(),
        witness: identity.witness.clone(),
    }
}

/// The action a dispatch performed, or None for an observation.
///
/// Observations return None rather than a placeholder: a snapshot performs no
/// navigation, and naming one would put a page load in the record of a read.
/// What a read is worth recording -- which page, when, under whose grant -- is
/// carried by the capability and identity beside this, not by an invented
/// action.
pub fn journal_action(capability: JournalCapability) -> Option<JournalAction> {
    Some(match capability {
        JournalCapability::Navigate => JournalAction::Navigate {
            url_redacted: "https://redacted.invalid".to_string(),
            wait: journal::NavigateWait::None,
        },
        JournalCapability::Click => JournalAction::Click {
            reference: "e1".to_string(),
            snapshot_id: "00000000000000000000000000000000".to_string(),
        },
        JournalCapability::ClickPoint => JournalAction::ClickPoint {
            snapshot_id: "00000000000000000000000000000000".to_string(),
            x_px: 0,
            y_px: 0,
        },
        JournalCapability::Type => JournalAction::Type {
            reference: "e1".to_string(),
            snapshot_id: "00000000000000000000000000000000".to_string(),
            text_bytes_utf8: 0,
            replace: false,
        },
        JournalCapability::Scroll => JournalAction::Scroll,
        JournalCapability::Snapshot
        | JournalCapability::Screenshot
        | JournalCapability::WaitFor
        | JournalCapability::Present
        | JournalCapability::ImportLogin
        | JournalCapability::CaptureLogin => return None,
    })
}

pub fn rejection_material(outcome: Outcome, detail: Value) -> RejectionMaterial {
    RejectionMaterial {
        intent_redacted: None,
        requested_severity: None,
        effective_severity: None,
        grant_decision: GrantDecision::not_reached(),
        governing_observation: GoverningObservation::observation_not_required(),
        action: None,
        locator: None,
        snapshot_ids: Vec::new(),
        outcome,
        detail,
    }
}

#[derive(Debug)]
struct ContextState {
    identity: RouteIdentity,
    epoch: DocumentEpoch,
    snapshots: BrowserSnapshotStore,
    tracker: Tracker,
    ended: bool,
    crashed: bool,
    next_snapshot_seed: u64,
    refs: refs::StableRefs,
}

fn public_read_frames(
    frames: &[snapshot_store::FrameDocument],
) -> Vec<snapshot_store::FrameDocument> {
    let mut readable = frames
        .iter()
        .filter(|frame| frame.parent_id.is_none())
        .cloned()
        .collect::<Vec<_>>();
    loop {
        let before = readable.len();
        for frame in frames {
            if frame
                .parent_id
                .as_ref()
                .is_some_and(|parent| readable.iter().any(|allowed| &allowed.frame_id == parent))
                && crate::browser_standing_grants::origin_is_public(&frame.origin)
                && !readable
                    .iter()
                    .any(|allowed| allowed.frame_id == frame.frame_id)
            {
                readable.push(frame.clone());
            }
        }
        if readable.len() == before {
            return readable;
        }
    }
}
impl ContextState {
    fn new(identity: RouteIdentity) -> Self {
        Self {
            identity,
            epoch: DocumentEpoch::new(),
            snapshots: BrowserSnapshotStore::new(8).expect("positive retention"),
            tracker: Tracker::default(),
            ended: false,
            crashed: false,
            next_snapshot_seed: 0,
            refs: refs::StableRefs::default(),
        }
    }
    fn snapshot_id(&mut self, kind: SnapshotKind) -> String {
        self.next_snapshot_seed = self.next_snapshot_seed.saturating_add(1);
        snapshot_store::new_snapshot_id(format!(
            "{}:{}:{}",
            self.identity.conversation_key,
            kind.as_str(),
            self.next_snapshot_seed
        ))
    }
}

/// A zoom must prove that the previously printed ref still names the same
/// browser node in the same document. Unknown or removed nodes show the outline;
/// missing identity evidence refuses rather than selecting by capture position.
fn zoom_target(
    context: &ContextState,
    requested: &str,
    refs: &[crate::snapshot_store::RefRecord],
    document: Option<&CommittedDocument>,
) -> Result<Option<String>, BrowserError> {
    let Some(shown) = context.refs.shown(requested) else {
        return Ok(None);
    };
    if shown.epoch != context.epoch.value()
        || matches!((&shown.document, document), (Some(old), Some(live)) if old.loader_id != live.loader_id)
    {
        return Err(BrowserError::StaleSnapshot {
            reason_code: "document_or_target_changed",
        });
    }
    if shown.record.backend_identity.is_none() {
        // Capture positions and role/name pairs can belong to replacement nodes.
        // Without a browser identity, an older snapshot cannot prove this ref.
        return Err(BrowserError::StaleSnapshot {
            reason_code: "ref_from_older_snapshot",
        });
    }
    Ok(refs
        .iter()
        .find(|fresh| {
            context
                .refs
                .resolves(requested, fresh, context.epoch.value(), document)
        })
        .map(|fresh| fresh.captured.reference.clone()))
}

#[derive(Debug, Default)]
struct BrowserState {
    contexts: HashMap<String, ContextState>,
    late_events: HashMap<String, VecDeque<LateEvent>>,
    operations: Vec<(String, Operation)>,
    invocations: HashMap<String, Vec<BrowserInvocation>>,
}

#[derive(Debug, Clone, Copy)]
struct BrowserInvocation {
    capability: BrowserCapability,
    outcome: Option<Outcome>,
}

#[derive(Debug, Default)]
enum BrowserRefusalRing {
    #[default]
    Disabled,
    Durable(Option<RefusalRing<SnapshotRefusalReason>>),
    InMemory(RefusalRing<SnapshotRefusalReason>),
}

#[derive(Clone, Copy, Default)]
enum BrowserJournalMode {
    #[default]
    Disabled,
    Durable(journal::JournalConfig),
    InMemory(journal::JournalConfig),
}

impl BrowserJournalMode {
    fn open_store(self) -> Result<Option<JournalStore>, JournalError> {
        match self {
            Self::Disabled => Ok(None),
            Self::Durable(config) => JournalStore::new(config).map(Some),
            Self::InMemory(config) => JournalStore::new_in_memory(config).map(Some),
        }
    }

    fn is_enabled(self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

#[derive(Default)]
struct BrowserJournalState {
    store: Option<JournalStore>,
    invocations: HashMap<String, Vec<JournalInvocation>>,
    authorization: HashMap<String, GrantDecision>,
}

impl BrowserJournalState {
    fn active_invocation_mut(
        &mut self,
        key: &str,
        capability: BrowserCapability,
    ) -> Option<(&mut JournalStore, &mut JournalInvocation)> {
        let store = self.store.as_mut()?;
        let invocation = self
            .invocations
            .get_mut(key)?
            .iter_mut()
            .rev()
            .find(|invocation| {
                invocation.browser_capability == capability && !invocation.terminal
            })?;
        Some((store, invocation))
    }

    fn release_terminal_invocations(&mut self, key: &str) {
        if let Some(invocations) = self.invocations.get_mut(key) {
            invocations.retain(|invocation| !invocation.terminal);
            if invocations.is_empty() {
                self.invocations.remove(key);
            }
        }
    }
}

pub struct BrowserPlane {
    state: Arc<Mutex<BrowserState>>,
    lanes: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    grants: Arc<Mutex<GrantStore>>,
    journal_mode: BrowserJournalMode,
    refusal_ring: Arc<Mutex<BrowserRefusalRing>>,
    journal: Arc<Mutex<BrowserJournalState>>,
    session_gate: Option<(
        crate::browser_session::BrowserSessions,
        Arc<cerebellum_core::clock::SystemClock>,
        u64,
    )>,
    result_schema_enforcement: ResultSchemaEnforcement,
    result_schema_findings: StdMutex<BTreeMap<CapabilityResultValidationError, u64>>,
}

impl Default for BrowserPlane {
    fn default() -> Self {
        Self::with_grants(GrantStore::default().with_public_web_baseline(Arc::new(
            crate::browser_signed_in::SignedInDomains::default(),
        )))
    }
}

impl BrowserPlane {
    pub(crate) async fn register_existing_profile(&self, identity: &RouteIdentity, uuid: &str) {
        let signed_in = self.grants.lock().await.signed_in_domains().cloned();
        if let Some(signed_in) = signed_in {
            let _ = signed_in.initialize_profile(
                &identity.agent_project_id,
                &crate::browser_signed_in::SignedInDomains::profile_name(identity),
                uuid,
                false,
            );
        }
        self.seed_legacy_profile(identity).await;
    }

    async fn seed_legacy_profile(&self, identity: &RouteIdentity) {
        let signed_in = self.grants.lock().await.signed_in_domains().cloned();
        let Some(signed_in) = signed_in else {
            return;
        };
        let profile = crate::browser_signed_in::SignedInDomains::profile_name(identity);
        let Some(uuid) = signed_in.needs_legacy_seed(&identity.agent_project_id, &profile) else {
            return;
        };
        let mut journal = self.journal.lock().await;
        if journal.store.is_none() {
            let Ok(store) = self.journal_mode.open_store() else {
                return;
            };
            journal.store = store;
        }
        let export = journal
            .store
            .as_ref()
            .map(|store| store.export())
            .unwrap_or_default();
        drop(journal);
        let evidence = crate::browser_signed_in::LoginJournalEvidence::from_export(
            &export,
            &identity.agent_project_id,
            &profile,
            &uuid,
        );
        let _ = signed_in.seed_legacy(&identity.agent_project_id, &profile, &uuid, evidence);
    }
    async fn remember_authorization(
        &self,
        identity: &RouteIdentity,
        decision: &crate::authorization::AuthorizationDecision,
    ) {
        self.journal.lock().await.authorization.insert(
            identity.conversation_key.clone(),
            GrantDecision {
                outcome: crate::journal::GrantOutcome::Allowed,
                reason: decision
                    .is_public_web_baseline()
                    .then(|| crate::authorization::PUBLIC_WEB_BASELINE.to_string()),
            },
        );
    }

    pub async fn record_signed_in(&self, profile: &str, origin: &str) -> Result<(), String> {
        let grants = self.grants.lock().await;
        grants
            .signed_in_domains()
            .ok_or("signed-in domains unavailable")?
            .record(profile, "default", origin)
    }
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_grants(grants: GrantStore) -> Self {
        Self {
            state: Arc::new(Mutex::new(BrowserState::default())),
            lanes: Arc::new(Mutex::new(HashMap::new())),
            grants: Arc::new(Mutex::new(grants)),
            journal_mode: BrowserJournalMode::Disabled,
            refusal_ring: Arc::new(Mutex::new(BrowserRefusalRing::Disabled)),
            journal: Arc::new(Mutex::new(BrowserJournalState::default())),
            session_gate: None,
            result_schema_enforcement: ResultSchemaEnforcement::DetectOnly,
            result_schema_findings: StdMutex::new(BTreeMap::new()),
        }
    }

    /// Select whether the serving boundary only records or withholds a reply
    /// that does not conform to its declared result schema.
    pub fn with_result_schema_enforcement(
        mut self,
        result_schema_enforcement: ResultSchemaEnforcement,
    ) -> Self {
        self.result_schema_enforcement = result_schema_enforcement;
        self
    }

    /// Distinct result-schema violations detected so far, with occurrence counts.
    pub fn result_schema_findings(&self) -> Vec<crate::computer_capability::ResultSchemaFinding> {
        let findings = self
            .result_schema_findings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        findings
            .iter()
            .map(
                |(error, occurrences)| crate::computer_capability::ResultSchemaFinding {
                    error: error.clone(),
                    occurrences: *occurrences,
                },
            )
            .collect()
    }

    pub fn with_session_gate(
        sessions: crate::browser_session::BrowserSessions,
        clock: Arc<cerebellum_core::clock::SystemClock>,
        navigation_settle_deadline_ms: u64,
    ) -> Self {
        Self {
            session_gate: Some((sessions, clock, navigation_settle_deadline_ms)),
            ..Self::new()
        }
    }

    /// Install grants on a plane that already has a session gate.
    ///
    /// Separate from [`Self::with_grants`] because a driving capability needs
    /// both, and the two constructors each reach `Self::default()` for the
    /// half they do not set -- so calling one after the other would discard
    /// whichever was applied first.
    pub fn with_grants_installed(mut self, grants: GrantStore) -> Self {
        self.grants = Arc::new(Mutex::new(grants));
        self
    }

    pub(crate) fn with_shared_grants(mut self, grants: Arc<Mutex<GrantStore>>) -> Self {
        self.grants = grants;
        self
    }

    /// How many loaded journal stores this plane retains.
    pub async fn retained_journal_store_count_for_test(&self) -> usize {
        usize::from(self.journal.lock().await.store.is_some())
    }

    #[doc(hidden)]
    pub async fn hold_journal_for_test(&self) -> impl Drop + '_ {
        self.journal.lock().await
    }

    /// Bytes still held by reservations that have not reached a terminal state.
    ///
    /// The export cannot answer this: it merges finalized entries with
    /// reservations in `dispatched` state, so a record appearing there proves
    /// the dispatch was committed and NOT that it was finalized. Zero here is
    /// what distinguishes "the journal closed this out" from "the journal is
    /// still holding it open" -- and an entry held open is what startup
    /// recovery reads as a process that died mid-dispatch.
    pub async fn active_reserved_bytes_for_test(&self) -> u64 {
        self.journal
            .lock()
            .await
            .store
            .as_ref()
            .map_or(0, |store| store.active_reserved_bytes())
    }

    /// Dispatches this plane committed and never closed out.
    ///
    /// Zero is the property crash coverage needs and neither the export nor the
    /// byte count can express: both read identically whether a dispatch was
    /// finalized or left open, and an open one is what startup recovery treats
    /// as a process that died mid-dispatch.
    pub async fn unfinalized_dispatch_count_for_test(&self) -> usize {
        self.journal
            .lock()
            .await
            .store
            .as_ref()
            .map_or(0, |store| store.unfinalized_dispatch_count())
    }

    pub async fn journal_handoff_opened(
        &self,
        identity: &RouteIdentity,
        origin: &str,
    ) -> Result<(), JournalError> {
        self.journal_handoff(
            identity,
            origin,
            journal::HandoffJournalOutcome::Opened,
            None,
        )
        .await
    }

    pub async fn journal_handoff_closed(
        &self,
        identity: &RouteIdentity,
        close: &crate::browser_session::HandoffClose,
    ) -> Result<(), JournalError> {
        let outcome = match close.outcome {
            crate::browser_session::HandoffOutcome::LoginObserved => {
                journal::HandoffJournalOutcome::LoginObserved
            }
            crate::browser_session::HandoffOutcome::Expired => {
                journal::HandoffJournalOutcome::Expired
            }
            crate::browser_session::HandoffOutcome::ClosedByCaller => {
                journal::HandoffJournalOutcome::ClosedByCaller
            }
        };
        self.journal_handoff(
            identity,
            &close.origin,
            outcome,
            Some(close.cookie_names_added as u64),
        )
        .await
    }

    /// Record only aggregate permission answers, never targets or screen text.
    pub(crate) async fn journal_would_ask(
        &self,
        identity: &RouteIdentity,
        principal: String,
        agent_id: &str,
        flow_id: &str,
        counts: Value,
    ) -> Result<(), JournalError> {
        if !self.journal_mode.is_enabled() {
            return Ok(());
        }
        let mut journal = self.journal.lock().await;
        if journal.store.is_none() {
            journal.store = self.journal_mode.open_store()?;
        }
        journal
            .store
            .as_mut()
            .expect("an enabled journal opens a store")
            .commit_would_ask(
                JournalIdentity {
                    principal,
                    ..journal_identity(identity)
                },
                agent_id,
                flow_id,
                counts,
            )
    }

    /// Record user-target actions without page text, typed text, or URL paths.
    /// Existing own-browser entries are deliberately unchanged.
    pub(crate) async fn journal_user_browser(
        &self,
        identity: &RouteIdentity,
        action: &str,
        origin: Option<&str>,
        outcome: &str,
        input_dispatched: Option<bool>,
    ) -> Result<(), JournalError> {
        if !self.journal_mode.is_enabled() {
            return Ok(());
        }
        let mut journal = self.journal.lock().await;
        if journal.store.is_none() {
            journal.store = self.journal_mode.open_store()?;
        }
        journal
            .store
            .as_mut()
            .expect("enabled journal opens a store")
            .commit_user_browser(
                journal_identity(identity),
                action,
                origin,
                outcome,
                input_dispatched,
            )
    }

    /// Record one login-import decision without cookie names or values.
    pub async fn journal_login_import(
        &self,
        identity: &RouteIdentity,
        origin: &str,
        outcome: &str,
        source_browser: Option<&str>,
        rows: u64,
    ) -> Result<(), JournalError> {
        if !self.journal_mode.is_enabled() {
            return Ok(());
        }
        let mut journal = self.journal.lock().await;
        if journal.store.is_none() {
            journal.store = self.journal_mode.open_store()?;
        }
        journal
            .store
            .as_mut()
            .expect("an enabled journal mode opens one store")
            .commit_login_import(
                journal_identity(identity),
                origin.to_string(),
                outcome.to_string(),
                source_browser.map(str::to_string),
                rows,
            )
    }

    /// Record one login-capture attempt. The payload type has no field that
    /// could carry a cookie name or value.
    pub async fn journal_login_capture(
        &self,
        identity: &RouteIdentity,
        payload: journal::LoginCapturePayload,
    ) -> Result<(), JournalError> {
        if !self.journal_mode.is_enabled() {
            return Ok(());
        }
        let mut journal = self.journal.lock().await;
        if journal.store.is_none() {
            journal.store = self.journal_mode.open_store()?;
        }
        match journal.store.as_mut() {
            Some(store) => store.commit_login_capture(journal_identity(identity), payload),
            // An enabled mode that opened no store is a journal that cannot
            // record; the caller refuses rather than acting unrecorded.
            None => Err(JournalError::internal_failure()),
        }
    }

    async fn journal_handoff(
        &self,
        identity: &RouteIdentity,
        origin: &str,
        outcome: journal::HandoffJournalOutcome,
        cookie_names_added: Option<u64>,
    ) -> Result<(), JournalError> {
        if !self.journal_mode.is_enabled() {
            return Ok(());
        }
        let mut journal = self.journal.lock().await;
        if journal.store.is_none() {
            journal.store = self.journal_mode.open_store()?;
        }
        journal
            .store
            .as_mut()
            .expect("an enabled journal mode opens one store")
            .commit_handoff(
                journal_identity(identity),
                origin.to_string(),
                outcome,
                cookie_names_added,
            )
    }

    /// The journal as a reader sees it, for tests that drive the lifecycle.
    pub async fn journal_export_for_test(&self) -> String {
        self.journal
            .lock()
            .await
            .store
            .as_ref()
            .map(JournalStore::export)
            .unwrap_or_default()
    }

    #[cfg(test)]
    pub async fn grant_count_for_test(&self) -> usize {
        self.grants.lock().await.current_grants().count()
    }

    /// Install a journal on a plane that already has a session gate.
    ///
    /// Chainable for the reason `with_grants_installed` is: a driving capability
    /// needs the session gate too, and a constructor reaching `Self::default()`
    /// would discard it.
    ///
    /// It replaces a `with_journal` constructor that built a plane with NO
    /// session gate, which could not drive anything and had zero callers -- so
    /// every reserve, commit and finalize on this path was unreachable code
    /// behind a flag nothing set. That is why the lifecycle test below is the
    /// first execution any of it has had.
    pub fn with_journal_installed(mut self, config: journal::JournalConfig) -> Self {
        self.journal_mode = BrowserJournalMode::Durable(config);
        self.journal = Arc::new(Mutex::new(BrowserJournalState::default()));
        self.refusal_ring = Arc::new(Mutex::new(BrowserRefusalRing::Durable(None)));
        self
    }

    /// Install a journal, durable or isolated as the caller states.
    ///
    /// One entry point taking a boolean rather than two constructors, because
    /// the two differ only in where bytes land and a caller choosing between
    /// them should see the choice at the call site rather than in a method
    /// name it might not read.
    pub fn with_journal_persistence(self, durable: bool, config: journal::JournalConfig) -> Self {
        if durable {
            self.with_journal_installed(config)
        } else {
            self.with_in_memory_journal(config)
        }
    }

    /// Install a journal that never touches the operator's durable audit data.
    ///
    /// Separate constructor rather than a parameter on the one above, so a
    /// fixture cannot reach the production path by leaving an argument at its
    /// default. The durable path is what a caller gets by asking for it.
    pub fn with_in_memory_journal(mut self, config: journal::JournalConfig) -> Self {
        self.journal_mode = BrowserJournalMode::InMemory(config);
        self.journal = Arc::new(Mutex::new(BrowserJournalState::default()));
        let ring = RefusalRing::new_in_memory(refusal_ring_config())
            .expect("the fixed browser refusal-ring capacity is valid");
        self.refusal_ring = Arc::new(Mutex::new(BrowserRefusalRing::InMemory(ring)));
        self
    }

    /// Serialize refusal state as JSON for test inspection.
    #[doc(hidden)]
    pub async fn refusal_ring_export_for_test(&self) -> String {
        let ring = self.refusal_ring.lock().await;
        let bytes = match &*ring {
            BrowserRefusalRing::Disabled | BrowserRefusalRing::Durable(None) => {
                return String::new()
            }
            BrowserRefusalRing::Durable(Some(ring)) | BrowserRefusalRing::InMemory(ring) => {
                ring.export_bytes()
            }
        }
        .expect("an in-process refusal state serializes");
        String::from_utf8(bytes).expect("JSON refusal state is UTF-8")
    }

    /// Typed refusal history for one caller.
    #[doc(hidden)]
    pub async fn refusal_history_for_test(
        &self,
        caller: &str,
    ) -> Option<CallerRefusalHistory<SnapshotRefusalReason>> {
        let ring = self.refusal_ring.lock().await;
        match &*ring {
            BrowserRefusalRing::Disabled | BrowserRefusalRing::Durable(None) => None,
            BrowserRefusalRing::Durable(Some(ring)) | BrowserRefusalRing::InMemory(ring) => {
                ring.history(caller).cloned()
            }
        }
    }

    /// Test seam for the per-context dispatch lane.
    ///
    /// The lane's mutual exclusion is an ordering property with no observable
    /// effect on any single call's result, so it cannot be asserted through the
    /// public dispatch surface alone.  Exposing the guard lets a test hold two
    /// lanes concurrently and observe that the same context never grants both.
    #[doc(hidden)]
    pub async fn lane_for_test(&self, key: &str) -> OwnedMutexGuard<()> {
        self.lane(key).await
    }

    async fn lane(&self, key: &str) -> OwnedMutexGuard<()> {
        let lane = {
            let mut lanes = self.lanes.lock().await;
            lanes
                .entry(key.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        lane.lock_owned().await
    }
    pub async fn open_context(&self, identity: RouteIdentity) -> Result<(), BrowserError> {
        let _lane = self.lane(&identity.conversation_key).await;
        let mut state = self.state.lock().await;
        // A successful launch replaces all state from the previous browser,
        // even if its idle or crash teardown did not mark that state ended.
        // Discard snapshots, document epochs, page tracking and crash flags so
        // the new browser cannot inherit a previous page's observations.
        // Snapshot and ref counters carry over without their old bindings:
        // restarting either counter would mint names a caller may still hold,
        // allowing a stale name to address a different page.
        let key = identity.conversation_key.clone();
        let next_snapshot_seed = state
            .contexts
            .get(&key)
            .map_or(0, |previous| previous.next_snapshot_seed);
        let refs = state
            .contexts
            .get(&key)
            .map(|previous| previous.refs.next_document())
            .unwrap_or_default();
        let mut context = ContextState::new(identity);
        context.refs = refs;
        context.next_snapshot_seed = next_snapshot_seed;
        state.contexts.insert(key.clone(), context);
        // Dialogs, downloads and policy rejections queued for the previous
        // browser describe pages that no longer exist; surfacing them from
        // browser.wait_for on the new browser would report events it never had.
        state.late_events.remove(&key);
        Ok(())
    }
    pub async fn end_context(&self, identity: &RouteIdentity, crashed: bool) {
        let _lane = self.lane(&identity.conversation_key).await;
        {
            let mut state = self.state.lock().await;
            if let Some(context) = state.contexts.get_mut(&identity.conversation_key) {
                context.ended = true;
                context.crashed = crashed;
                context.snapshots.begin_teardown();
                let _ = context.snapshots.complete_teardown();
                context.refs.prune_shown(&context.snapshots);
            }
        }
        self.journal
            .lock()
            .await
            .invocations
            .remove(&identity.conversation_key);
    }
    pub async fn queue_event(&self, identity: &RouteIdentity, event: LateEvent) {
        let mut state = self.state.lock().await;
        state
            .late_events
            .entry(identity.conversation_key.clone())
            .or_default()
            .push_back(event);
    }
    pub async fn operation_log(&self) -> Vec<(String, Operation)> {
        self.state.lock().await.operations.clone()
    }

    /// Test seam for checking that nested browser operations retain distinct
    /// capability outcomes even when the durable journal cannot name one.
    pub async fn invocation_outcomes_for_test(
        &self,
        identity: &RouteIdentity,
    ) -> Vec<(BrowserCapability, Option<Outcome>)> {
        self.state
            .lock()
            .await
            .invocations
            .get(&identity.conversation_key)
            .into_iter()
            .flatten()
            .map(|invocation| (invocation.capability, invocation.outcome))
            .collect()
    }

    fn op(state: &mut BrowserState, key: &str, operation: Operation) {
        state.operations.push((key.to_string(), operation));
    }

    fn record_invocation_outcome(
        state: &mut BrowserState,
        key: &str,
        capability: BrowserCapability,
        outcome: Outcome,
    ) {
        if let Some(invocation) = state.invocations.get_mut(key).and_then(|invocations| {
            invocations.iter_mut().rev().find(|invocation| {
                invocation.capability == capability && invocation.outcome.is_none()
            })
        }) {
            invocation.outcome = Some(outcome);
        }
    }

    pub async fn dispatch(
        &self,
        identity: &RouteIdentity,
        capability: BrowserCapability,
        args: &Value,
    ) -> Value {
        // Route admission is performed by lib.rs. This lane is still required
        // for direct first-party callers because it serializes all CDP operations
        // for a conversation and prevents concurrent invocations from interleaving them.
        let _lane = self.lane(&identity.conversation_key).await;
        self.journal
            .lock()
            .await
            .authorization
            .remove(&identity.conversation_key);
        self.seed_legacy_profile(identity).await;
        if let Some((sessions, clock, _)) = &self.session_gate {
            if let Some(handoff) =
                sessions.human_in_control(&identity.conversation_key, clock.as_ref())
            {
                return self
                    .result(
                        identity,
                        Err(BrowserError::HumanInControl {
                            origin: handoff.origin,
                            expires_in_ms: handoff.expires_in_ms,
                        }),
                    )
                    .await;
            }
        }
        let start = self.state.lock().await.operations.len();
        let result = self.dispatch_inner(identity, capability, args).await;
        if let Err(error) = &result {
            self.terminal_on_error(identity, capability, start, error)
                .await;
        }
        self.result(identity, result).await
    }

    /// Serve one browser capability and certify its completed reply before it
    /// reaches the module wire.
    pub async fn serve(
        &self,
        identity: &RouteIdentity,
        capability: BrowserCapability,
        args: &Value,
    ) -> Result<Value, CapabilityResultValidationError> {
        let reply = self.dispatch(identity, capability, args).await;
        self.finish_reply(capability.name(), reply)
    }

    pub(crate) fn finish_reply(
        &self,
        capability_id: &str,
        reply: Value,
    ) -> Result<Value, CapabilityResultValidationError> {
        match validate_browser_result(capability_id, &reply) {
            Ok(()) => Ok(reply),
            Err(error) => {
                let mut findings = self
                    .result_schema_findings
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let occurrences = findings.entry(error.clone()).or_default();
                *occurrences = occurrences.saturating_add(1);
                drop(findings);

                match self.result_schema_enforcement {
                    ResultSchemaEnforcement::DetectOnly => Ok(reply),
                    ResultSchemaEnforcement::Withhold => Err(error),
                }
            }
        }
    }

    async fn dispatch_inner(
        &self,
        identity: &RouteIdentity,
        capability: BrowserCapability,
        args: &Value,
    ) -> Result<Value, BrowserError> {
        match capability {
            BrowserCapability::Navigate => self.navigate(identity, args).await,
            BrowserCapability::Snapshot => self.snapshot(identity, args).await,
            BrowserCapability::Click => self.click(identity, args).await,
            BrowserCapability::Type => self.type_text(identity, args).await,
            BrowserCapability::Screenshot => self.screenshot(identity, args).await,
            BrowserCapability::Scroll => self.scroll(identity, args).await,
            BrowserCapability::ClickPoint => self.click_point(identity, args).await,
            BrowserCapability::WaitFor => self.wait_for(identity, args).await,
        }
    }

    async fn terminal_on_error(
        &self,
        identity: &RouteIdentity,
        capability: BrowserCapability,
        start: usize,
        error: &BrowserError,
    ) {
        let operations = self.state.lock().await.operations[start..].to_vec();
        let committed = operations
            .iter()
            .any(|(_, operation)| *operation == Operation::CommitDispatched);
        let finalized = operations.iter().any(|(_, operation)| {
            matches!(
                *operation,
                Operation::FinalizeRejected | Operation::FinalizeDispatched
            )
        });
        if finalized
            || !operations
                .iter()
                .any(|(_, operation)| *operation == Operation::Reserve)
        {
            return;
        }
        let outcome = journal_outcome(error);
        let detail = journal_refusal_detail(error);
        if committed {
            let mut state = self.state.lock().await;
            Self::record_invocation_outcome(
                &mut state,
                &identity.conversation_key,
                capability,
                outcome,
            );
            Self::op(
                &mut state,
                &identity.conversation_key,
                Operation::FinalizeDispatched,
            );
            drop(state);
            let mut journal = self.journal.lock().await;
            if let Some((store, invocation)) =
                journal.active_invocation_mut(&identity.conversation_key, capability)
            {
                let _ = invocation.finalize_dispatched(
                    store,
                    FinalContextAssociation {
                        profile_uuid: None,
                        profile_name: None,
                    },
                    CompletedResult { outcome, detail },
                );
            }
            journal.release_terminal_invocations(&identity.conversation_key);
        } else {
            let mut state = self.state.lock().await;
            Self::record_invocation_outcome(
                &mut state,
                &identity.conversation_key,
                capability,
                outcome,
            );
            Self::op(
                &mut state,
                &identity.conversation_key,
                Operation::FinalizeRejected,
            );
            drop(state);
            let mut journal = self.journal.lock().await;
            if let Some((store, invocation)) =
                journal.active_invocation_mut(&identity.conversation_key, capability)
            {
                let _ = invocation.finalize_rejected(store, rejection_material(outcome, detail));
            }
            journal.release_terminal_invocations(&identity.conversation_key);
        }
    }

    async fn result(&self, identity: &RouteIdentity, result: Result<Value, BrowserError>) -> Value {
        let context = BrowserContextResult::from_identity(identity).json();
        match result {
            Ok(mut value) => {
                if let Some(object) = value.as_object_mut() {
                    object.insert("context".into(), context);
                }
                value
            }
            Err(error) => {
                let mut object = Map::new();
                object.insert("outcome".into(), Value::String(error.outcome().into()));
                object.insert("remedy".into(), Value::String(error.remedy().into()));
                object.insert("context".into(), context);
                if let Some(detail) = error.detail() {
                    object.insert("detail".into(), detail);
                }
                if let BrowserError::SessionStateUnavailable = error {
                    object.insert(
                        "stage".into(),
                        Value::String(crate::browser_session::BROWSER_SESSION_LOCK_STAGE.into()),
                    );
                }
                if let BrowserError::HumanInControl {
                    origin,
                    expires_in_ms,
                } = error
                {
                    object.insert("origin".into(), Value::String(origin));
                    object.insert("expires_in_ms".into(), json!(expires_in_ms));
                }
                Value::Object(object)
            }
        }
    }

    async fn validate_request<'a>(
        &self,
        args: &'a Value,
        allowed: &[&str],
    ) -> Result<&'a Map<String, Value>, BrowserError> {
        let object = args
            .as_object()
            .ok_or_else(|| BrowserError::InvalidRequest {
                field: "$".into(),
                reason_code: "wrong_type",
            })?;
        if let Some(field) = object
            .keys()
            .filter(|field| !allowed.contains(&field.as_str()))
            .min()
        {
            return Err(BrowserError::InvalidRequest {
                field: field.clone(),
                reason_code: "unknown_field",
            });
        }
        Ok(object)
    }

    async fn reserve(
        &self,
        identity: &RouteIdentity,
        capability: BrowserCapability,
    ) -> Result<Option<crate::browser_session::OperationGuard>, BrowserError> {
        self.reserve_inner(identity, capability, true).await
    }

    async fn reserve_inner(
        &self,
        identity: &RouteIdentity,
        capability: BrowserCapability,
        persist_journal: bool,
    ) -> Result<Option<crate::browser_session::OperationGuard>, BrowserError> {
        let operation = self.admit_operation(identity, capability)?;
        self.reserve_journal(identity, capability, persist_journal)
            .await?;
        Ok(operation)
    }

    /// Admit one operation on the route's browser session without opening a
    /// journal entry. Page reads use this to ask the browser where its page is
    /// before deciding whether the read is authorized, so a refused read still
    /// leaves nothing in the actuation journal.
    fn admit_operation(
        &self,
        identity: &RouteIdentity,
        capability: BrowserCapability,
    ) -> Result<Option<crate::browser_session::OperationGuard>, BrowserError> {
        Ok(if let Some((sessions, clock, _)) = &self.session_gate {
            match sessions.accept_dispatch(&identity.conversation_key, clock.as_ref()) {
                crate::browser_session::DispatchAdmission::Accepted(guard) => Some(guard),
                crate::browser_session::DispatchAdmission::LaunchPending => {
                    return if capability == BrowserCapability::Navigate {
                        Err(BrowserError::NoSession)
                    } else {
                        Err(BrowserError::BrowserLaunchPending)
                    }
                }
                crate::browser_session::DispatchAdmission::NoSession => {
                    return Err(BrowserError::NoSession)
                }
                crate::browser_session::DispatchAdmission::StateUnavailable => {
                    return Err(BrowserError::SessionStateUnavailable)
                }
            }
        } else if matches!(
            capability,
            BrowserCapability::Navigate | BrowserCapability::Snapshot
        ) {
            return Err(BrowserError::NoSession);
        } else {
            None
        })
    }

    async fn reserve_journal(
        &self,
        identity: &RouteIdentity,
        capability: BrowserCapability,
        persist_journal: bool,
    ) -> Result<(), BrowserError> {
        if persist_journal && self.journal_mode.is_enabled() {
            let mut journal = self.journal.lock().await;
            if journal.store.is_none() {
                journal.store = self.journal_mode.open_store().map_err(map_journal_error)?;
            }
            let mut invocation = JournalInvocation::new(capability);
            invocation
                .reserve(
                    journal
                        .store
                        .as_mut()
                        .expect("an enabled journal mode opens one store"),
                    journal_identity(identity),
                )
                .map_err(map_journal_error)?;
            journal
                .invocations
                .entry(identity.conversation_key.clone())
                .or_default()
                .push(invocation);
        }
        let mut state = self.state.lock().await;
        state
            .invocations
            .entry(identity.conversation_key.clone())
            .or_default()
            .push(BrowserInvocation {
                capability,
                outcome: None,
            });
        Self::op(&mut state, &identity.conversation_key, Operation::Reserve);
        Ok(())
    }
    async fn commit(
        &self,
        identity: &RouteIdentity,
        capability: BrowserCapability,
    ) -> Result<(), BrowserError> {
        if !crate::grant_enforcement::commit_current() {
            return Err(BrowserError::AuthorizationDenied {
                reason: "grant_revoked",
            });
        }
        if self.journal_mode.is_enabled() {
            let mut journal = self.journal.lock().await;
            let grant_decision = journal
                .authorization
                .remove(&identity.conversation_key)
                .unwrap_or_else(GrantDecision::not_reached);
            if let Some((store, invocation)) =
                journal.active_invocation_mut(&identity.conversation_key, capability)
            {
                invocation
                    .commit_dispatched(
                        store,
                        DispatchMaterial {
                            intent_redacted: None,
                            requested_severity: None,
                            effective_severity: None,
                            grant_decision,
                            action: journal_action(invocation.capability),
                            locator: None,
                            snapshot_ids: Vec::new(),
                            governing_observation: GoverningObservation::observation_not_required(),
                        },
                    )
                    .map_err(map_journal_error)?;
            }
        }
        // The browser plane's dispatch commitment, reached before any CDP
        // command and only once the journal (when enabled) has committed. The
        // journal's own commit marks the request too; with the journal
        // disabled this is the only mark.
        identity.witness.mark_committed();
        let mut state = self.state.lock().await;
        Self::op(
            &mut state,
            &identity.conversation_key,
            Operation::CommitDispatched,
        );
        Ok(())
    }
    async fn finalize(
        &self,
        identity: &RouteIdentity,
        capability: BrowserCapability,
        outcome: Outcome,
        detail: Value,
    ) -> Result<(), BrowserError> {
        let mut state = self.state.lock().await;
        Self::record_invocation_outcome(
            &mut state,
            &identity.conversation_key,
            capability,
            outcome,
        );
        Self::op(
            &mut state,
            &identity.conversation_key,
            Operation::FinalizeDispatched,
        );
        drop(state);
        if self.journal_mode.is_enabled() {
            let mut journal = self.journal.lock().await;
            if let Some((store, invocation)) =
                journal.active_invocation_mut(&identity.conversation_key, capability)
            {
                invocation
                    .finalize_dispatched(
                        store,
                        FinalContextAssociation {
                            profile_uuid: None,
                            profile_name: identity.resolve_profile().profile_name,
                        },
                        CompletedResult { outcome, detail },
                    )
                    .map_err(map_journal_error)?;
            }
            journal.release_terminal_invocations(&identity.conversation_key);
        }
        Ok(())
    }

    async fn navigate(
        &self,
        identity: &RouteIdentity,
        args: &Value,
    ) -> Result<Value, BrowserError> {
        let object = self
            .validate_request(
                args,
                &[
                    "url",
                    "intent",
                    "wait",
                    "severity",
                    "read_page",
                    "max_bytes",
                ],
            )
            .await?;
        let url = required_string(object, "url", 1, 4096)?;
        let _intent = bounded_string(object, "intent", 0, 512)?;
        let read_page = match object.get("read_page") {
            None => false,
            Some(Value::Bool(value)) => *value,
            Some(_) => {
                return Err(BrowserError::InvalidRequest {
                    field: "read_page".into(),
                    reason_code: "wrong_type",
                })
            }
        };
        let read_max_bytes = optional_integer(object, "max_bytes", 1, 262_144)?
            .unwrap_or(DEFAULT_READ_PAGE_MAX_BYTES) as usize;
        let wait = match object.get("wait") {
            None => crate::browser_session::NavigationWait::Settle,
            Some(Value::String(value)) if value == "settle" => {
                crate::browser_session::NavigationWait::Settle
            }
            Some(Value::String(value)) if value == "none" => {
                crate::browser_session::NavigationWait::None
            }
            Some(Value::String(_)) => {
                return Err(BrowserError::InvalidRequest {
                    field: "wait".into(),
                    reason_code: "unsupported_value",
                })
            }
            Some(_) => {
                return Err(BrowserError::InvalidRequest {
                    field: "wait".into(),
                    reason_code: "wrong_type",
                })
            }
        };
        let requested_severity = parse_severity(object)?;
        let scheme = url
            .split_once(':')
            .map(|(scheme, _)| scheme)
            .unwrap_or_default();
        if scheme.is_empty()
            || !url.contains("://")
            || scheme.len() > 64
            || scheme.bytes().any(|byte| {
                !byte.is_ascii_lowercase()
                    && !byte.is_ascii_digit()
                    && byte != b'+'
                    && byte != b'-'
                    && byte != b'.'
            })
        {
            return Err(BrowserError::InvalidRequest {
                field: "url".into(),
                reason_code: "unsupported_value",
            });
        }
        let authority = url
            .split_once("://")
            .and_then(|(_, rest)| rest.split(['/', '?', '#']).next())
            .unwrap_or_default();
        if authority.is_empty() || authority.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(BrowserError::InvalidRequest {
                field: "url".into(),
                reason_code: "unsupported_value",
            });
        }
        if url.contains('@')
            && url.find("//").is_some_and(|start| {
                url[start + 2..]
                    .split('/')
                    .next()
                    .is_some_and(|authority| authority.contains('@'))
            })
        {
            return Err(BrowserError::InvalidRequest {
                field: "url".into(),
                reason_code: "unsupported_value",
            });
        }
        {
            let origin = origin_from_url(url);
            let decision = self
                .grants
                .lock()
                .await
                .authorize(
                    AuthorizationRequest::navigate(
                        &identity.conversation_key,
                        requested_severity,
                        url,
                        &identity.agent_project_id,
                    ),
                    &origin,
                )
                .map_err(map_authorization_error)?;
            self.remember_authorization(identity, &decision).await;
        }
        if scheme != "http" && scheme != "https" {
            return Err(BrowserError::NavigationPolicyRejected {
                reason_code: "scheme_not_allowed",
            });
        }
        let Some(mut session_operation) =
            self.reserve(identity, BrowserCapability::Navigate).await?
        else {
            return Err(BrowserError::NoSession);
        };
        self.commit(identity, BrowserCapability::Navigate).await?;
        let tracker = {
            let mut state = self.state.lock().await;
            let tracker = {
                let context = state
                    .contexts
                    .entry(identity.conversation_key.clone())
                    .or_insert_with(|| ContextState::new(identity.clone()));
                let _ = context
                    .epoch
                    .replace(DocumentTransition::TopLevelDocumentReplaced);
                context.tracker = Tracker::default();
                context.tracker.token("navigation_started");
                context.tracker.clone()
            };
            Self::op(
                &mut state,
                &identity.conversation_key,
                Operation::CdpNavigate,
            );
            tracker
        };
        let deadline_ms = self
            .session_gate
            .as_ref()
            .map(|(_, _, deadline_ms)| *deadline_ms)
            .ok_or(BrowserError::NoSession)?;
        let route_key = identity.conversation_key.clone();
        let requested_url = url.to_string();
        let driven = tokio::task::spawn_blocking(move || {
            let mut tracker = tracker;
            let result = session_operation.navigate(
                &route_key,
                &requested_url,
                wait,
                deadline_ms,
                &mut tracker,
            );
            (session_operation, tracker, result)
        })
        .await
        .map_err(|_| BrowserError::Internal {
            reason_code: JournalReasonCode::InternalFailure,
        })?;
        let (session_operation, tracker, drive_result) = driven;
        session_operation.finish();
        {
            let mut state = self.state.lock().await;
            let context = state
                .contexts
                .get_mut(&identity.conversation_key)
                .ok_or(BrowserError::NoSession)?;
            context.tracker = tracker.clone();
        }
        drive_result.map_err(map_navigation_drive_error)?;

        let should_settle = wait == crate::browser_session::NavigationWait::Settle;
        let mut response = navigate_reply(&tracker, should_settle);
        let outcome = if response["outcome"] == "ok" {
            Outcome::Success
        } else if response["outcome"] == "unsupported_download" {
            Outcome::Denied
        } else {
            Outcome::InternalError
        };
        self.finalize(
            identity,
            BrowserCapability::Navigate,
            outcome,
            response.clone(),
        )
        .await?;
        if !read_page {
            return Ok(response);
        }

        // Action grants are scoped by ORIGIN and SEVERITY TIER, not by capability,
        // so a same-origin navigation grant also admits a snapshot. That is the
        // model, decided rather than inherited: "act but not read" is not a real
        // power (every actuation targets a ref only a snapshot can produce),
        // "read but not act" already exists as an observe-tier grant, and the
        // origin is the confidentiality boundary the web itself enforces, so
        // an action axis would multiply consent prompts without narrowing
        // anything the origin does not already narrow. The read still
        // authorizes against the URL the page is on when it is read, not the
        // one requested, because a redirect can leave the granted origin.
        //
        // The read journals under its own capability. It did not when this landed
        // -- the vocabulary had no Snapshot member, so recording the read would
        // have written it as a navigation -- and that hole closed when the
        // members were added rather than by anything here changing.
        let read_start = self.state.lock().await.operations.len();
        let mut page = match self
            .capture_snapshot(
                identity,
                SnapshotKind::Actionable,
                read_max_bytes,
                true,
                None,
                &state_text::Filters::default(),
            )
            .await
        {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.terminal_on_error(identity, BrowserCapability::Snapshot, read_start, &error)
                    .await;
                partial_error_result(&error)
            }
        };
        let response_object = response
            .as_object_mut()
            .expect("navigation response is an object");
        // The page text sits at the top of the reply, where Prefrontal lifts
        // it into a text part, exactly as a snapshot reply carries it.
        if let Some(text) = page
            .as_object_mut()
            .and_then(|page| page.remove(state_text::STATE_TEXT_FIELD))
        {
            response_object.insert(state_text::STATE_TEXT_FIELD.into(), text);
        }
        response_object.insert("read_page".into(), page);
        Ok(response)
    }

    async fn snapshot(
        &self,
        identity: &RouteIdentity,
        args: &Value,
    ) -> Result<Value, BrowserError> {
        let object = self
            .validate_request(
                args,
                &["mode", "max_bytes", "zoom", "text_filter", "role_filter"],
            )
            .await?;
        let kind = match object.get("mode") {
            None => SnapshotKind::Actionable,
            Some(Value::String(value)) if value == "actionable" => SnapshotKind::Actionable,
            Some(Value::String(value)) if value == "ax" => SnapshotKind::Ax,
            Some(Value::String(value)) if value == "dom_full" => SnapshotKind::DomFull,
            Some(Value::String(_)) => {
                return Err(BrowserError::InvalidRequest {
                    field: "mode".into(),
                    reason_code: "unsupported_value",
                })
            }
            Some(_) => {
                return Err(BrowserError::InvalidRequest {
                    field: "mode".into(),
                    reason_code: "wrong_type",
                })
            }
        };
        let max_bytes =
            optional_integer(object, "max_bytes", 1, 262_144)?.unwrap_or(65_536) as usize;
        let zoom = match object.get("zoom") {
            None => None,
            // Zoom selects a subtree of the page text, which only the default
            // view prints; the ax and dom_full views have no outline to narrow.
            Some(Value::String(value))
                if snapshot_store::valid_ref(value) && kind == SnapshotKind::Actionable =>
            {
                Some(value.clone())
            }
            Some(Value::String(_)) => {
                return Err(BrowserError::InvalidRequest {
                    field: "zoom".into(),
                    reason_code: "unsupported_value",
                })
            }
            Some(_) => {
                return Err(BrowserError::InvalidRequest {
                    field: "zoom".into(),
                    reason_code: "wrong_type",
                })
            }
        };
        let filters = state_text::Filters::parse(object, kind)?;
        self.capture_snapshot(identity, kind, max_bytes, true, zoom.as_deref(), &filters)
            .await
    }

    async fn record_snapshot_refusal(
        &self,
        identity: &RouteIdentity,
        claimed_addressing: &str,
        reason: SnapshotRefusalReason,
    ) -> Result<(), BrowserError> {
        let mut binding = self.refusal_ring.lock().await;
        let ring = match &mut *binding {
            BrowserRefusalRing::Disabled => return Ok(()),
            BrowserRefusalRing::InMemory(ring) => ring,
            BrowserRefusalRing::Durable(slot) => {
                if slot.is_none() {
                    let path = journal_data_path(BROWSER_REFUSAL_RING_FILE).map_err(|_| {
                        BrowserError::Internal {
                            reason_code: JournalReasonCode::InternalFailure,
                        }
                    })?;
                    *slot = Some(RefusalRing::new(path, refusal_ring_config()).map_err(|_| {
                        BrowserError::Internal {
                            reason_code: JournalReasonCode::InternalFailure,
                        }
                    })?);
                }
                slot.as_mut().expect("initialized above")
            }
        };
        ring.record_refusal(&identity.agent_project_id, claimed_addressing, reason)
            .map_err(|_| BrowserError::Internal {
                reason_code: JournalReasonCode::InternalFailure,
            })
    }

    /// Ask the browser which document its main frame has committed to.
    ///
    /// The tracker records the last navigation this module started or saw a
    /// click start. A page can leave that document on its own -- a timer, a
    /// meta refresh, a script assigning `location`, a redirect that lands after
    /// a click's observation window -- and the tracker would still name the old
    /// origin. Reads authorize against this document's URL instead, because a
    /// grant is the person's consent to one origin being read and the content
    /// a read returns is whatever the page currently shows.
    async fn read_live_document(
        &self,
        identity: &RouteIdentity,
        mut session_operation: crate::browser_session::OperationGuard,
        deadline_ms: u64,
    ) -> Result<(crate::browser_session::OperationGuard, CommittedDocument), BrowserError> {
        let route_key = identity.conversation_key.clone();
        let (session_operation, live) = tokio::task::spawn_blocking(move || {
            let live = session_operation.committed_document(&route_key, deadline_ms);
            (session_operation, live)
        })
        .await
        .map_err(|_| BrowserError::Internal {
            reason_code: JournalReasonCode::InternalFailure,
        })?;
        Ok((session_operation, live.map_err(map_navigation_drive_error)?))
    }

    /// Authorize one page read against the page's live URL, recording a
    /// consent refusal in the refusal ring rather than the actuation journal.
    async fn authorize_read(
        &self,
        identity: &RouteIdentity,
        capability: BrowserCapability,
        live_url: &str,
    ) -> Result<bool, BrowserError> {
        let origin = origin_from_url(live_url);
        let grants = self.grants.lock().await;
        let request = if capability == BrowserCapability::Screenshot {
            AuthorizationRequest::screenshot(
                &identity.conversation_key,
                live_url,
                &identity.agent_project_id,
            )
        } else {
            AuthorizationRequest::snapshot(
                &identity.conversation_key,
                live_url,
                &identity.agent_project_id,
            )
        };
        let (error, reason) = match grants.authorize(request, &origin) {
            Ok(decision) => {
                if grants.commit(&decision).is_ok() {
                    self.remember_authorization(identity, &decision).await;
                    return Ok(decision.is_public_web_baseline());
                }
                (
                    BrowserError::AuthorizationDenied { reason: "no_grant" },
                    SnapshotRefusalReason::NoGrant,
                )
            }
            Err(
                error @ (crate::authorization::AuthorizationError::NoGrant
                | crate::authorization::AuthorizationError::NoGrantForAction { .. }),
            ) => (
                map_authorization_error(error),
                SnapshotRefusalReason::NoGrant,
            ),
            Err(error @ crate::authorization::AuthorizationError::OriginScope { .. }) => (
                map_authorization_error(error),
                SnapshotRefusalReason::OriginScope,
            ),
            Err(error) => return Err(map_authorization_error(error)),
        };
        drop(grants);
        self.record_snapshot_refusal(identity, live_url, reason)
            .await?;
        Err(error)
    }

    /// Refuse a completed capture whose page committed any navigation while
    /// it was being taken.
    ///
    /// Authorization and capture are separate CDP calls, and a page can commit
    /// a navigation between them or during a multi-call capture. Comparing
    /// origins is not enough: a page that goes to another origin and comes
    /// back reads the same origin at both ends while the capture returned the
    /// middle document's content, read without consent. So any change to the
    /// committed document -- its history entry, the history around it, or its
    /// loader -- refuses, even a same-origin or same-document one. The
    /// captured content is dropped by the caller; this records the refusal and
    /// closes the already-dispatched journal entry as denied.
    async fn confirm_read_document(
        &self,
        identity: &RouteIdentity,
        capability: BrowserCapability,
        authorized: &CommittedDocument,
        live_after: Result<CommittedDocument, crate::browser_session::NavigationDriveError>,
    ) -> Result<(), BrowserError> {
        let live_after = live_after.map_err(map_navigation_drive_error)?;
        if live_after == *authorized {
            return Ok(());
        }
        let error = BrowserError::PageNavigatedDuringRead {
            authorized_origin: origin_from_url(&authorized.url),
            live_origin: origin_from_url(&live_after.url),
        };
        self.record_snapshot_refusal(
            identity,
            &live_after.url,
            SnapshotRefusalReason::PageNavigatedDuringRead,
        )
        .await?;
        self.finalize(
            identity,
            capability,
            Outcome::Denied,
            error.detail().unwrap_or(Value::Null),
        )
        .await?;
        Err(error)
    }

    async fn capture_snapshot(
        &self,
        identity: &RouteIdentity,
        kind: SnapshotKind,
        max_bytes: usize,
        persist_journal: bool,
        zoom: Option<&str>,
        filters: &state_text::Filters,
    ) -> Result<Value, BrowserError> {
        let document_epoch = {
            let state = self.state.lock().await;
            state
                .contexts
                .get(&identity.conversation_key)
                .filter(|context| !context.ended)
                .ok_or(BrowserError::NoSession)?
                .epoch
                .value()
        };
        let deadline_ms = self
            .session_gate
            .as_ref()
            .map(|(_, _, deadline_ms)| *deadline_ms)
            .ok_or(BrowserError::NoSession)?;
        let Some(session_operation) =
            self.admit_operation(identity, BrowserCapability::Snapshot)?
        else {
            return Err(BrowserError::NoSession);
        };
        let (mut session_operation, source_document) = self
            .read_live_document(identity, session_operation, deadline_ms)
            .await?;
        let baseline_read = self
            .authorize_read(identity, BrowserCapability::Snapshot, &source_document.url)
            .await?;
        let route = identity.conversation_key.clone();
        let (operation, frames) = tokio::task::spawn_blocking(move || {
            let frames = session_operation.frame_documents(&route, deadline_ms);
            (session_operation, frames)
        })
        .await
        .map_err(|_| BrowserError::Internal {
            reason_code: JournalReasonCode::InternalFailure,
        })?;
        session_operation = operation;
        let frames = frames.map_err(map_navigation_drive_error)?;
        let zoom_reference = if let Some(requested) = zoom {
            let state = self.state.lock().await;
            let context = state
                .contexts
                .get(&identity.conversation_key)
                .ok_or(BrowserError::NoSession)?;
            // Reject refs from another document before looking up their backend
            // node. Before printing, also compare the freshly captured target,
            // frame, backend id, loader, session and origin with the retained ref.
            zoom_target(context, requested, &[], Some(&source_document))?;
            context
                .refs
                .shown(requested)
                .map(|shown| shown.record.clone())
        } else {
            None
        };
        if zoom_reference
            .as_ref()
            .and_then(|reference| reference.frame_document.as_ref())
            .is_some_and(|frame| !frames.iter().any(|live| live.same_document(frame)))
        {
            return Err(BrowserError::StaleSnapshot {
                reason_code: "frame_document_changed",
            });
        }
        // A person's top-page grant retains inherited frame access. Implicit
        // public browsing is not approval to read embedded local/private content.
        let readable_frames = if baseline_read {
            public_read_frames(&frames)
        } else {
            frames.clone()
        };
        let frames_omitted = frames.len().saturating_sub(readable_frames.len());
        if !frames.is_empty() {
            session_operation
                .set_read_frames(readable_frames)
                .map_err(map_navigation_drive_error)?;
        }
        self.reserve_journal(identity, BrowserCapability::Snapshot, persist_journal)
            .await?;
        self.commit(identity, BrowserCapability::Snapshot).await?;
        {
            let mut state = self.state.lock().await;
            Self::op(
                &mut state,
                &identity.conversation_key,
                Operation::CdpObserve,
            );
        }

        let route_key = identity.conversation_key.clone();
        let authorized_url = source_document.url.clone();
        let driven = tokio::task::spawn_blocking(move || {
            let result = if let Some(reference) = zoom_reference.as_ref() {
                session_operation.snapshot_subtree_classified(
                    &route_key,
                    kind,
                    reference,
                    document_epoch,
                    &authorized_url,
                    deadline_ms,
                )
            } else {
                session_operation.snapshot_classified(
                    &route_key,
                    kind,
                    document_epoch,
                    &authorized_url,
                    deadline_ms,
                )
            };
            // Read which document the page shows once the capture has
            // returned, on the same admitted operation, so nothing this module
            // issues can sit between the capture and this check.
            // A failed capture returns no page content. Do not spend a second
            // deadline checking its document while the renderer is still busy.
            let live_after = match &result {
                Err(
                    error @ crate::browser_session::NavigationDriveError::CommandDeadline { .. },
                ) => Err(error.clone()),
                _ => session_operation.committed_document(&route_key, deadline_ms),
            };
            (session_operation, result, live_after)
        })
        .await
        .map_err(|_| BrowserError::Internal {
            reason_code: JournalReasonCode::InternalFailure,
        })?;
        let (session_operation, drive_result, live_after) = driven;
        session_operation.finish();
        let mut observation = match drive_result {
            Ok(observation) => observation,
            Err(error) => {
                // A capture fails when the page commits another document
                // while it is being read: Chrome answers the accessibility
                // read with "Invalid ID" once the nodes it named are gone
                // (`examples/handoff_attachment_probe.rs` records it). The
                // caller can act on that move, so it is reported as the move
                // rather than as a module failure.
                if live_after
                    .as_ref()
                    .is_ok_and(|live| *live != source_document)
                {
                    self.confirm_read_document(
                        identity,
                        BrowserCapability::Snapshot,
                        &source_document,
                        live_after,
                    )
                    .await?;
                }
                let error = map_navigation_drive_error(error);
                if let BrowserError::PageNavigatedDuringRead { live_origin, .. } = &error {
                    self.record_snapshot_refusal(
                        identity,
                        live_origin,
                        SnapshotRefusalReason::PageNavigatedDuringRead,
                    )
                    .await?;
                    self.finalize(
                        identity,
                        BrowserCapability::Snapshot,
                        Outcome::Denied,
                        error.detail().unwrap_or(Value::Null),
                    )
                    .await?;
                }
                return Err(error);
            }
        };
        self.confirm_read_document(
            identity,
            BrowserCapability::Snapshot,
            &source_document,
            live_after,
        )
        .await?;
        if frames_omitted > 0 {
            let note = "embedded frame from a local, private or opaque origin omitted; it needs site permission";
            observation.records.push(AxRecord {
                depth: 0,
                role: "StaticText".into(),
                name: note.into(),
                value: None,
                reference: None,
            });
            observation
                .dom_text
                .get_or_insert_with(String::new)
                .push_str(&format!("\n<!-- {note} -->\n"));
        }
        let (result, ref_count) = self
            .retain_text_snapshot_inner(
                identity,
                kind,
                &observation.records,
                observation.dom_text.as_deref(),
                observation.refs,
                &observation.facts,
                zoom,
                filters,
                max_bytes,
                // Omitted AX subtrees or embedded documents make the
                // observation partial even when DOM-full text was requested.
                frames_omitted > 0 || observation.ax_truncated,
                observation.refs_truncated,
                Some(source_document),
            )
            .await?;
        // The journal records sizes, never page text: the page text's bytes
        // and how many refs it names.
        let content_bytes = result
            .get(state_text::STATE_TEXT_FIELD)
            .and_then(Value::as_str)
            .map(str::len)
            .unwrap_or_default();
        self.finalize(
            identity,
            BrowserCapability::Snapshot,
            Outcome::Success,
            json!({
                "outcome": "ok",
                "snapshot_id": result["snapshot_id"],
                "content_bytes": content_bytes,
                "ref_count": ref_count,
                "truncated": result["truncated"],
                "refs_truncated": result["refs_truncated"],
            }),
        )
        .await?;
        Ok(result)
    }

    /// Retain a completed extraction observation supplied by the CDP adapter.
    /// The adapter performs DOM/AX traversal; this method performs bounded wire
    /// encoding and retention only.
    #[allow(clippy::too_many_arguments)]
    pub async fn retain_text_snapshot(
        &self,
        identity: &RouteIdentity,
        mode: SnapshotKind,
        records: &[AxRecord],
        dom_text: Option<&str>,
        refs: Vec<crate::snapshot_store::RefRecord>,
        max_bytes: usize,
        // The document the adapter read. An action on this snapshot is
        // refused unless the page still shows this document, so `None` makes
        // the snapshot unusable for actions.
        source_document: Option<CommittedDocument>,
    ) -> Result<Value, BrowserError> {
        let _lane = self.lane(&identity.conversation_key).await;
        let no_facts = HashMap::new();
        self.retain_text_snapshot_inner(
            identity,
            mode,
            records,
            dom_text,
            refs,
            &no_facts,
            None,
            &state_text::Filters::default(),
            max_bytes,
            false,
            false,
            source_document,
        )
        .await
        .map(|(reply, _)| reply)
    }

    #[allow(clippy::too_many_arguments)]
    async fn retain_text_snapshot_inner(
        &self,
        identity: &RouteIdentity,
        mode: SnapshotKind,
        records: &[AxRecord],
        dom_text: Option<&str>,
        refs: Vec<crate::snapshot_store::RefRecord>,
        facts: &HashMap<String, state_text::NodeFacts>,
        zoom: Option<&str>,
        filters: &state_text::Filters,
        max_bytes: usize,
        content_incomplete: bool,
        refs_incomplete: bool,
        // The document the read was authorized against; its URL becomes the
        // snapshot's source. `None` only for an observation handed in without
        // one, whose source falls back to the tracked page.
        source_document: Option<CommittedDocument>,
    ) -> Result<(Value, usize), BrowserError> {
        let mut state = self.state.lock().await;
        let context = state
            .contexts
            .get_mut(&identity.conversation_key)
            .ok_or(BrowserError::NoSession)?;
        if context.ended {
            return Err(BrowserError::NoSession);
        }
        let mut records = records.to_vec();
        let mut facts = facts.clone();
        let mut refs = refs;
        context.refs.assign(
            &mut records,
            &mut refs,
            &mut facts,
            context.epoch.value(),
            source_document.as_ref(),
        );
        let refs_truncated = refs.len() > MAX_REFS || refs_incomplete;
        let mut refs = refs.into_iter().take(MAX_REFS).collect::<Vec<_>>();
        let id = context.snapshot_id(mode);
        let source_origin = source_document
            .as_ref()
            .map(|document| document.url.clone())
            .unwrap_or_else(|| {
                context
                    .tracker
                    .url_final
                    .clone()
                    .unwrap_or_else(|| "null".into())
            });
        let (content, encoded_truncated, schema, prior_cut) = match mode {
            SnapshotKind::Actionable => {
                let target = match zoom {
                    Some(requested) => {
                        zoom_target(context, requested, &refs, source_document.as_ref())?
                    }
                    None => None,
                };
                let rendered = state_text::render(&state_text::RenderInput {
                    records: &records,
                    facts: &facts,
                    filters,
                    page_url: &source_origin,
                    snapshot_id: &id,
                    zoom: zoom.map(|requested| state_text::Zoom {
                        requested,
                        target: target.as_deref(),
                    }),
                    max_bytes,
                });
                // A ref stays usable only if the caller was shown it.
                refs.retain(|record| rendered.printed_refs.contains(&record.captured.reference));
                (
                    rendered.text,
                    rendered.cut_lines > 0,
                    snapshot_store::STATE_TEXT_SCHEMA,
                    (rendered.cut_bytes, rendered.cut_lines),
                )
            }
            SnapshotKind::Ax => {
                let (content, truncated) = snapshot_store::encode_ax_jsonl(&records, usize::MAX)
                    .map_err(map_snapshot_error)?;
                (content, truncated, AX_SCHEMA, (0, 0))
            }
            SnapshotKind::DomFull => {
                let (content, truncated) =
                    snapshot_store::encode_dom_text(dom_text.unwrap_or_default(), usize::MAX);
                (content, truncated, DOM_SCHEMA, (0, 0))
            }
            SnapshotKind::Screenshot => {
                return Err(BrowserError::InvalidRequest {
                    field: "mode".into(),
                    reason_code: "unsupported_value",
                })
            }
        };
        let truncated = encoded_truncated || content_incomplete || refs_truncated;
        let mut snapshot = TextSnapshot {
            snapshot_id: id.clone(),
            kind: mode,
            document_epoch: context.epoch.value(),
            source_origin,
            source_document,
            content_schema: schema,
            content,
            truncated,
            refs_truncated,
            refs,
        };
        let mut reply = snapshot_store::bounded_text_reply(
            &mut snapshot,
            max_bytes,
            prior_cut,
            BrowserContextResult::from_identity(identity).json(),
        );
        let ref_count = snapshot.refs.len();
        context
            .snapshots
            .retain_text(snapshot)
            .map_err(map_snapshot_error)?;
        if let Some(snapshot_store::StoredSnapshot::Text(retained)) = context.snapshots.get(&id) {
            context.refs.remember(
                &retained.refs,
                &id,
                retained.document_epoch,
                retained.source_document.as_ref(),
            );
        }
        context.refs.prune_shown(&context.snapshots);
        // The outer reply owns the dispatch envelope: navigate embeds this
        // snapshot without a second context.
        reply
            .as_object_mut()
            .expect("snapshot object")
            .remove("context");
        Ok((reply, ref_count))
    }

    /// Close an already-committed action that `check_snapshot_document`
    /// stopped before any input. When the page no longer shows the snapshot's
    /// document, the action is journaled with the stale-snapshot outcome, the
    /// same outcome a click gets when its target's form classification
    /// changed since the snapshot. A failure to read the page is left to the
    /// ordinary error path.
    async fn refuse_moved_page<T>(
        &self,
        identity: &RouteIdentity,
        capability: BrowserCapability,
        drive_result: Result<T, BrowserError>,
    ) -> Result<T, BrowserError> {
        let error = match drive_result {
            Ok(result) => return Ok(result),
            Err(error) => error,
        };
        if matches!(
            error,
            BrowserError::PageChangedSinceSnapshot { .. } | BrowserError::StaleSnapshot { .. }
        ) {
            self.finalize(
                identity,
                capability,
                Outcome::StaleSnapshot,
                error.detail().unwrap_or_else(|| json!({})),
            )
            .await?;
        }
        Err(error)
    }

    async fn unpin_snapshot(&self, identity: &RouteIdentity, snapshot_id: &str) {
        let mut state = self.state.lock().await;
        if let Some(context) = state.contexts.get_mut(&identity.conversation_key) {
            context.snapshots.unpin(snapshot_id);
        }
    }

    pub async fn snapshot_pin_count_for_test(
        &self,
        identity: &RouteIdentity,
        snapshot_id: &str,
    ) -> usize {
        self.state
            .lock()
            .await
            .contexts
            .get(&identity.conversation_key)
            .map(|context| context.snapshots.pin_count(snapshot_id))
            .unwrap_or_default()
    }

    pub async fn text_snapshot_pin_count_for_test(
        &self,
        identity: &RouteIdentity,
        snapshot_id: &str,
    ) -> usize {
        self.snapshot_pin_count_for_test(identity, snapshot_id)
            .await
    }

    /// Build a click's reply from what the driver measured, and record a
    /// navigation the click caused as the conversation's current page.
    ///
    /// Recording it keeps the tracked page, and the `url_final` later replies
    /// report, in step with the browser. Reads do not rely on it: a snapshot
    /// or screenshot asks the browser for its committed URL and authorizes
    /// against that.
    async fn click_reply(
        &self,
        identity: &RouteIdentity,
        outcome: crate::browser_session::BrowserClickOutcome,
    ) -> Value {
        use crate::browser_session::{BrowserClickOutcome, ClickNavigation};
        let (dialogs, navigation) = match outcome {
            BrowserClickOutcome::Clicked { navigation, .. } => (Vec::new(), navigation),
            BrowserClickOutcome::JavaScriptDialogDismissed {
                dialogs,
                navigation,
                ..
            } => (dialogs, navigation),
        };
        let mut response = match navigation {
            ClickNavigation::NoneObserved { window_ms } => json!({
                "outcome":"ok",
                "navigation":"none_observed",
                "navigation_window_ms":window_ms,
            }),
            ClickNavigation::SameDocument { url } => {
                // A same-document change cannot leave the origin, so the
                // document epoch and its snapshots stay valid.
                if let Some(context) = self
                    .state
                    .lock()
                    .await
                    .contexts
                    .get_mut(&identity.conversation_key)
                {
                    context.tracker.url_final = Some(url.clone());
                }
                json!({"outcome":"ok","navigation":"same_document","url_final":url})
            }
            ClickNavigation::MainFrame(tracker) if tracker.download_blocked => {
                let mut response = navigate_reply(&tracker, false);
                response["navigation"] = json!("not_committed");
                response
            }
            ClickNavigation::MainFrame(tracker) if tracker.navigation_ended_without_commit() => {
                // The page the click started from is still the one shown.
                json!({
                    "outcome":"ok",
                    "navigation":"not_committed",
                    "lifecycle":{"events":[],"loaded":false,"settled":false},
                })
            }
            ClickNavigation::MainFrame(tracker) => {
                if let Some(context) = self
                    .state
                    .lock()
                    .await
                    .contexts
                    .get_mut(&identity.conversation_key)
                {
                    let _ = context
                        .epoch
                        .replace(DocumentTransition::TopLevelDocumentReplaced);
                    context.tracker = (*tracker).clone();
                }
                let mut response = navigate_reply(&tracker, true);
                let object = response
                    .as_object_mut()
                    .expect("navigation response is an object");
                object.insert("navigation".into(), json!("main_frame"));
                if let Some(error_text) = tracker.main_frame_failure() {
                    let failed = BrowserError::NavigationFailed {
                        error_text: error_text.to_string(),
                    };
                    object.insert("outcome".into(), json!(failed.outcome()));
                    object.insert("remedy".into(), json!(failed.remedy()));
                    object.insert("detail".into(), failed.detail().unwrap_or(Value::Null));
                }
                if let Some(url_final) = tracker.url_final.as_deref() {
                    // The same check the next snapshot runs, made without
                    // committing, so the caller learns before reading whether
                    // that read will be refused and which origin to request.
                    let landing_origin = origin_from_url(url_final);
                    let granted = self
                        .grants
                        .lock()
                        .await
                        .authorize(
                            AuthorizationRequest::snapshot(
                                &identity.conversation_key,
                                url_final,
                                &identity.agent_project_id,
                            ),
                            &landing_origin,
                        )
                        .is_ok();
                    object.insert("landing_origin".into(), json!(landing_origin));
                    object.insert("landing_origin_granted".into(), json!(granted));
                }
                response
            }
        };
        if !dialogs.is_empty() {
            let object = response
                .as_object_mut()
                .expect("click response is an object");
            if object.get("outcome") == Some(&json!("ok")) {
                object.insert("outcome".into(), json!("javascript_dialog_dismissed"));
            }
            // Dialog details have their own field. Lifecycle describes document
            // navigation consistently, even when a dialog opened without one.
            object
                .entry("lifecycle")
                .or_insert_with(|| json!({"events":[],"loaded":false,"settled":false}));
            object.insert(
                "dialogs".into(),
                dialogs
                    .into_iter()
                    .map(|dialog| {
                        json!({
                            "dialog_type": dialog.dialog_type,
                            "response": dialog.response.as_str(),
                        })
                    })
                    .collect(),
            );
        }
        response
    }

    async fn click(&self, identity: &RouteIdentity, args: &Value) -> Result<Value, BrowserError> {
        let object = self
            .validate_request(args, &["ref", "snapshot_id", "intent", "severity"])
            .await?;
        let reference = required_string(object, "ref", 2, 21)?;
        let snapshot_id = required_string(object, "snapshot_id", 32, 32)?;
        if !snapshot_store::valid_snapshot_id(snapshot_id) {
            return Err(BrowserError::InvalidRequest {
                field: "snapshot_id".into(),
                reason_code: "unsupported_value",
            });
        }
        if !snapshot_store::valid_ref(reference) {
            return Err(BrowserError::InvalidRequest {
                field: "ref".into(),
                reason_code: "unsupported_value",
            });
        }
        bounded_string(object, "intent", 0, 512)?;
        // The floor is enforced by authorization below, which is also where the
        // target's required severity is computed; refusing there lets the
        // refusal carry that exact value instead of a second estimate.
        let requested_severity = parse_severity(object)?;
        let (
            backend_identity,
            classification,
            document_epoch,
            source_origin,
            source_document,
            frame_document,
        ) = {
            let mut state = self.state.lock().await;
            let context = state
                .contexts
                .get_mut(&identity.conversation_key)
                .ok_or(BrowserError::NoSession)?;
            if context.ended {
                return Err(BrowserError::NoSession);
            }
            let snapshot = context
                .snapshots
                .pin_text(snapshot_id, context.epoch.value())
                .map_err(map_snapshot_error)?;
            let Some(record) = snapshot
                .refs
                .iter()
                .find(|record| record.captured.reference == reference)
            else {
                context.snapshots.unpin(snapshot_id);
                return Err(BrowserError::RefNotFound {
                    reference: reference.to_string(),
                });
            };
            let Some(backend_identity) = record.backend_identity.clone() else {
                context.snapshots.unpin(snapshot_id);
                return Err(BrowserError::ElementIntercepted);
            };
            (
                backend_identity,
                record.classification.clone().map(|record| *record),
                snapshot.document_epoch,
                record
                    .frame_document
                    .as_ref()
                    .map(|frame| frame.origin.clone())
                    .unwrap_or_else(|| snapshot.source_origin.clone()),
                snapshot.source_document.clone(),
                record.frame_document.clone(),
            )
        };

        if let Err(reason) = &classification {
            self.unpin_snapshot(identity, snapshot_id).await;
            return Err(BrowserError::ClassificationUnavailable(reason.clone()));
        }
        let activated_element = classification
            .as_ref()
            .ok()
            .map(|record| json!({"identity":record.activation_target_identity,"kind":record.target_kind}));
        let deadline_ms = self
            .session_gate
            .as_ref()
            .map(|(_, _, deadline_ms)| *deadline_ms);
        // Before mouse input, recompute the snapshot classification so a changed
        // target cannot inherit authorization from the earlier observation.

        let authorization = {
            let grants = self.grants.lock().await;
            let request = match classification.as_ref() {
                Ok(classification) => AuthorizationRequest::click(
                    &identity.conversation_key,
                    requested_severity,
                    snapshot_id,
                    &identity.agent_project_id,
                    classification,
                ),
                Err(_) => AuthorizationRequest::click_unverified(
                    &identity.conversation_key,
                    requested_severity,
                    snapshot_id,
                    &identity.agent_project_id,
                ),
            };
            let origin = origin_from_url(&source_origin);
            grants.authorize(request, &origin).and_then(|decision| {
                grants
                    .commit(&decision)
                    .map_err(|_| crate::authorization::AuthorizationError::NoGrant)?;
                Ok(decision)
            })
        };
        if let Err(error) = authorization {
            self.unpin_snapshot(identity, snapshot_id).await;
            let mut error = map_authorization_error(error);
            if let (
                BrowserError::HazardNotDisclosed {
                    classification_unavailable,
                    ..
                }
                | BrowserError::SeverityBelowFloor {
                    classification_unavailable,
                    ..
                },
                Err(reason),
            ) = (&mut error, &classification)
            {
                *classification_unavailable = Some(reason.clone());
            }
            return Err(error);
        }

        self.remember_authorization(
            identity,
            authorization.as_ref().expect("authorization succeeded"),
        )
        .await;

        let reservation = self.reserve(identity, BrowserCapability::Click).await;
        let mut session_operation = match reservation {
            Ok(Some(operation)) => operation,
            Ok(None) => {
                self.unpin_snapshot(identity, snapshot_id).await;
                return Err(BrowserError::NoSession);
            }
            Err(error) => {
                self.unpin_snapshot(identity, snapshot_id).await;
                return Err(error);
            }
        };
        if let Err(error) = self.commit(identity, BrowserCapability::Click).await {
            session_operation.finish();
            self.unpin_snapshot(identity, snapshot_id).await;
            return Err(error);
        }
        {
            let mut state = self.state.lock().await;
            Self::op(
                &mut state,
                &identity.conversation_key,
                Operation::CdpObserve,
            );
        }

        let Some(deadline_ms) = deadline_ms else {
            session_operation.finish();
            self.unpin_snapshot(identity, snapshot_id).await;
            return Err(BrowserError::NoSession);
        };
        let state = Arc::clone(&self.state);
        let route_key = identity.conversation_key.clone();
        let expected_classification = classification.ok();
        let origin = source_origin;
        let driven = tokio::task::spawn_blocking(move || {
            // Lock order: this callback runs inside the driver call, while the
            // session's driver lock is held, and it takes the browser state
            // lock. So nothing may call into the browser sessions (status,
            // admission, driver calls, close or teardown) while holding the
            // browser state lock; that would take the two in the other order.
            let mut input_dispatched = |event| {
                let operation = match event {
                    crate::browser_session::BrowserInputEvent::Press(_) => Operation::CdpInputPress,
                    crate::browser_session::BrowserInputEvent::Release(_) => {
                        Operation::CdpInputRelease
                    }
                };
                let mut state = state.blocking_lock();
                Self::op(&mut state, &route_key, operation);
            };
            // Checked on this operation immediately before input, so the
            // document the click lands in is the one the snapshot read.
            let live = session_operation.committed_document(&route_key, deadline_ms);
            if let Err(error) = check_snapshot_document(source_document.as_ref(), live) {
                return (session_operation, Err(error));
            }
            if let Some(frame) = &frame_document {
                match session_operation.prepare_frame(&route_key, frame, deadline_ms) {
                    Ok(true) => {}
                    _ => {
                        return (
                            session_operation,
                            Err(BrowserError::StaleSnapshot {
                                reason_code: "frame_document_changed",
                            }),
                        )
                    }
                }
            }
            let result = session_operation.click_classified(
                &route_key,
                &backend_identity,
                document_epoch,
                &origin,
                expected_classification.as_ref(),
                deadline_ms,
                &mut input_dispatched,
            );
            (session_operation, Ok(result))
        })
        .await;
        let (session_operation, drive_result) = match driven {
            Ok(result) => result,
            Err(_) => {
                self.unpin_snapshot(identity, snapshot_id).await;
                return Err(BrowserError::Internal {
                    reason_code: JournalReasonCode::InternalFailure,
                });
            }
        };
        session_operation.finish();
        self.unpin_snapshot(identity, snapshot_id).await;
        let drive_result = self
            .refuse_moved_page(identity, BrowserCapability::Click, drive_result)
            .await?;

        let mut response = match drive_result {
            Ok(outcome) => self.click_reply(identity, outcome).await,
            Err(crate::browser_session::ClickDriveError::Intercepted(detail)) => {
                return Err(BrowserError::Intercepted(detail));
            }
            Err(crate::browser_session::ClickDriveError::NoPosition) => {
                return Err(BrowserError::ElementIntercepted);
            }
            Err(crate::browser_session::ClickDriveError::ClassificationChanged) => {
                return Err(BrowserError::StaleSnapshot {
                    reason_code: "classification_changed",
                });
            }
            Err(crate::browser_session::ClickDriveError::OutsideViewportAfterScroll(refusal)) => {
                return Err(BrowserError::OutsideViewportAfterScroll { refusal });
            }
            Err(crate::browser_session::ClickDriveError::Navigation(error)) => {
                return Err(map_navigation_drive_error(error));
            }
        };
        response["activated_element"] = activated_element.unwrap_or(Value::Null);
        self.finalize(
            identity,
            BrowserCapability::Click,
            if response["outcome"] == "unsupported_download" {
                Outcome::Denied
            } else {
                Outcome::Success
            },
            response.clone(),
        )
        .await?;
        Ok(response)
    }

    async fn screenshot(
        &self,
        identity: &RouteIdentity,
        args: &Value,
    ) -> Result<Value, BrowserError> {
        let object = self
            .validate_request(args, &["max_bytes", "full", "path"])
            .await?;
        if object.contains_key("path") {
            return Err(BrowserError::InvalidRequest {
                field: "path".into(),
                reason_code: "path_abandons_custody",
            });
        }
        let max_bytes = optional_integer(object, "max_bytes", 1, MAX_ENCODED_PNG_BYTES as u64)?
            .unwrap_or(MAX_ENCODED_PNG_BYTES as u64) as usize;
        let full = optional_bool(object, "full")?.unwrap_or(false);
        let document_epoch = {
            let state = self.state.lock().await;
            state
                .contexts
                .get(&identity.conversation_key)
                .filter(|context| !context.ended)
                .ok_or(BrowserError::NoSession)?
                .epoch
                .value()
        };
        let deadline_ms = self
            .session_gate
            .as_ref()
            .map(|(_, _, deadline_ms)| *deadline_ms)
            .ok_or(BrowserError::NoSession)?;
        let Some(session_operation) =
            self.admit_operation(identity, BrowserCapability::Screenshot)?
        else {
            return Err(BrowserError::NoSession);
        };
        // As for a snapshot: pixels of an authenticated page are a read of it,
        // so the grant consulted is the one for where the page is now.
        let (mut session_operation, source_document) = self
            .read_live_document(identity, session_operation, deadline_ms)
            .await?;
        self.authorize_read(
            identity,
            BrowserCapability::Screenshot,
            &source_document.url,
        )
        .await?;
        let route = identity.conversation_key.clone();
        let (operation, frames) = tokio::task::spawn_blocking(move || {
            let frames = session_operation.frame_documents(&route, deadline_ms);
            (session_operation, frames)
        })
        .await
        .map_err(|_| BrowserError::Internal {
            reason_code: JournalReasonCode::InternalFailure,
        })?;
        session_operation = operation;
        let frames = frames.map_err(map_navigation_drive_error)?;
        let captured_frames = frames.clone();
        self.reserve_journal(identity, BrowserCapability::Screenshot, true)
            .await?;
        self.commit(identity, BrowserCapability::Screenshot).await?;
        {
            let mut state = self.state.lock().await;
            Self::op(
                &mut state,
                &identity.conversation_key,
                Operation::CdpObserve,
            );
        }

        let route_key = identity.conversation_key.clone();
        let driven = tokio::task::spawn_blocking(move || {
            let result =
                session_operation.screenshot(&route_key, document_epoch, deadline_ms, full);
            // Read which document the page shows on the same admitted
            // operation right after the capture, so nothing this module issues
            // can sit between the capture and the check that it read the
            // authorized document.
            let live_after = session_operation.committed_document(&route_key, deadline_ms);
            (session_operation, result, live_after)
        })
        .await
        .map_err(|_| BrowserError::Internal {
            reason_code: JournalReasonCode::InternalFailure,
        })?;
        let (session_operation, drive_result, live_after) = driven;
        session_operation.finish();
        let observation = drive_result.map_err(map_navigation_drive_error)?;
        self.confirm_read_document(
            identity,
            BrowserCapability::Screenshot,
            &source_document,
            live_after,
        )
        .await?;
        let bytes = observation.image_png_b64.len();
        if bytes > max_bytes {
            return Err(BrowserError::ImageTooLarge {
                bytes,
                bound_bytes: max_bytes,
            });
        }
        let png = validate_png_base64_dimensions(&observation.image_png_b64)
            .map_err(map_coordinate_error)?;
        let payload =
            ScreenshotPayload::new(observation.image_png_b64, png.width_px(), png.height_px());
        let result = self
            .retain_screenshot_inner(
                identity,
                payload,
                observation.before,
                observation.after,
                observation.invalidation_observed,
                Some(source_document),
                captured_frames,
            )
            .await?;
        self.finalize(
            identity,
            BrowserCapability::Screenshot,
            Outcome::Success,
            json!({
                "outcome": "ok",
                "snapshot_id": result["snapshot_id"],
                "bytes": bytes,
                "image_width_px": result["image_width_px"],
                "image_height_px": result["image_height_px"],
            }),
        )
        .await?;
        Ok(result)
    }

    async fn click_point(
        &self,
        identity: &RouteIdentity,
        args: &Value,
    ) -> Result<Value, BrowserError> {
        let object = self
            .validate_request(
                args,
                &[
                    "snapshot_id",
                    "x_px",
                    "y_px",
                    "image_width_px",
                    "image_height_px",
                    "intent",
                    "severity",
                ],
            )
            .await?;
        let snapshot_id = required_string(object, "snapshot_id", 32, 32)?;
        if !snapshot_store::valid_snapshot_id(snapshot_id) {
            return Err(BrowserError::InvalidRequest {
                field: "snapshot_id".into(),
                reason_code: "unsupported_value",
            });
        }
        let x = required_signed_integer(object, "x_px")?;
        let y = required_signed_integer(object, "y_px")?;
        // The image the caller was addressing. A pixel coordinate means nothing
        // without the image it indexes, and these two numbers disagreeing with
        // what was retained is the only evidence available that the caller was
        // looking at a different copy of it.
        let addressed_width = required_signed_integer(object, "image_width_px")?;
        let addressed_height = required_signed_integer(object, "image_height_px")?;
        bounded_string(object, "intent", 0, 512)?;
        // As in `click`: authorization enforces the floor and reports the
        // severity it computed for this action.
        let requested_severity = parse_severity(object)?;
        let (position, source_origin, source_document, document_epoch, screenshot_frames) = {
            let mut state = self.state.lock().await;
            let context = state
                .contexts
                .get_mut(&identity.conversation_key)
                .ok_or(BrowserError::NoSession)?;
            if context.ended {
                return Err(BrowserError::NoSession);
            }
            let screenshot = context
                .snapshots
                .pin(snapshot_id, SnapshotKind::Screenshot, context.epoch.value())
                .map_err(map_snapshot_error)?;
            // `pin` refuses a kind mismatch, so a non-screenshot should not reach
            // here. Return the typed refusal anyway rather than panicking, and
            // balance the pin if that invariant ever changes.
            let screenshot = match screenshot {
                snapshot_store::StoredSnapshot::Screenshot(snapshot) => snapshot,
                snapshot_store::StoredSnapshot::Text(_) => {
                    context.snapshots.unpin(snapshot_id);
                    return Err(map_snapshot_error(SnapshotError::WrongKind));
                }
            };
            // Checked before the coordinate is mapped and before anything is
            // dispatched. A coordinate from a differently-sized copy lands
            // inside the bounds of the retained image, so the mapping below
            // would succeed and actuate at a point the caller never chose.
            if i128::from(screenshot.image_width_px) != addressed_width
                || i128::from(screenshot.image_height_px) != addressed_height
            {
                context.snapshots.unpin(snapshot_id);
                return Err(BrowserError::InvalidCoordinates {
                    reason: InvalidCoordinatesReason::ImageSizeMismatch,
                });
            }

            let transform = TransformInputs::new(
                screenshot.input_rect,
                screenshot.device_scale_factor,
                screenshot.visual_viewport_scale,
            );
            let mapped = map_pixel_to_css(
                transform,
                screenshot.image_width_px,
                screenshot.image_height_px,
                x,
                y,
            );
            let (x_css, y_css) = match mapped {
                Ok(point) => point,
                Err(error) => {
                    context.snapshots.unpin(snapshot_id);
                    return Err(map_coordinate_error(error));
                }
            };
            (
                crate::browser_session::BrowserClickPosition { x_css, y_css },
                screenshot.source_origin,
                screenshot.source_document,
                screenshot.document_epoch,
                screenshot.frame_documents,
            )
        };

        let reservation = self.reserve(identity, BrowserCapability::ClickPoint).await;
        let mut session_operation = match reservation {
            Ok(Some(operation)) => operation,
            Ok(None) => {
                self.unpin_snapshot(identity, snapshot_id).await;
                return Err(BrowserError::NoSession);
            }
            Err(error) => {
                self.unpin_snapshot(identity, snapshot_id).await;
                return Err(error);
            }
        };

        {
            let mut state = self.state.lock().await;
            Self::op(
                &mut state,
                &identity.conversation_key,
                Operation::CdpObserve,
            );
        }

        let Some(deadline_ms) = self
            .session_gate
            .as_ref()
            .map(|(_, _, deadline_ms)| *deadline_ms)
        else {
            session_operation.finish();
            self.unpin_snapshot(identity, snapshot_id).await;
            return Err(BrowserError::NoSession);
        };
        let route_key = identity.conversation_key.clone();
        let origin = source_origin.clone();
        let observed = tokio::task::spawn_blocking(move || {
            let live = session_operation.committed_document(&route_key, deadline_ms);
            let result = check_snapshot_document(source_document.as_ref(), live).and_then(|_| {
                let live_frames = session_operation
                    .frame_documents(&route_key, deadline_ms)
                    .map_err(map_navigation_drive_error)?;
                if !screenshot_frames.is_empty() && live_frames != screenshot_frames {
                    return Err(BrowserError::StaleSnapshot {
                        reason_code: "frame_document_changed",
                    });
                }
                session_operation
                    .classify_point(&route_key, position, document_epoch, &origin, deadline_ms)
                    .map_err(map_navigation_drive_error)?
                    .map_err(BrowserError::ClassificationUnavailable)
            });
            let frame = session_operation.point_frame_document();
            (session_operation, result, source_document, frame)
        })
        .await;
        let (operation, classification, source_document, frame_document) = match observed {
            Ok(value) => value,
            Err(_) => {
                self.unpin_snapshot(identity, snapshot_id).await;
                return Err(BrowserError::Internal {
                    reason_code: JournalReasonCode::InternalFailure,
                });
            }
        };
        session_operation = operation;
        let frame_document = frame_document.map_err(map_navigation_drive_error)?;
        let source_origin = frame_document
            .as_ref()
            .map(|frame| frame.origin.clone())
            .unwrap_or(source_origin);
        let classification = match classification {
            Ok(record) => record,
            Err(error) => {
                session_operation.finish();
                self.unpin_snapshot(identity, snapshot_id).await;
                return Err(error);
            }
        };
        let authorization = {
            let grants = self.grants.lock().await;
            let request = AuthorizationRequest::click_point(
                &identity.conversation_key,
                requested_severity,
                snapshot_id,
                &identity.agent_project_id,
                &classification,
            );
            grants
                .authorize(request, &origin_from_url(&source_origin))
                .and_then(|decision| {
                    grants
                        .commit(&decision)
                        .map_err(|_| crate::authorization::AuthorizationError::NoGrant)?;
                    Ok(decision)
                })
        };
        if let Err(error) = authorization {
            session_operation.finish();
            self.unpin_snapshot(identity, snapshot_id).await;
            return Err(map_authorization_error(error));
        }
        self.remember_authorization(
            identity,
            authorization.as_ref().expect("authorization succeeded"),
        )
        .await;
        if let Err(error) = self.commit(identity, BrowserCapability::ClickPoint).await {
            session_operation.finish();
            self.unpin_snapshot(identity, snapshot_id).await;
            return Err(error);
        }
        let activated_element = json!({"identity":classification.activation_target_identity,"kind":classification.target_kind});
        let state = Arc::clone(&self.state);
        let route_key = identity.conversation_key.clone();
        let driven = tokio::task::spawn_blocking(move || {
            // Same lock order as the classified click: this callback holds
            // the session's driver lock when it takes the browser state lock.
            let mut input_dispatched = |event| {
                let operation = match event {
                    crate::browser_session::BrowserInputEvent::Press(_) => Operation::CdpInputPress,
                    crate::browser_session::BrowserInputEvent::Release(_) => {
                        Operation::CdpInputRelease
                    }
                };
                let mut state = state.blocking_lock();
                Self::op(&mut state, &route_key, operation);
            };
            // As in `click`: the pixels map onto the captured document only.
            let live = session_operation.committed_document(&route_key, deadline_ms);
            if let Err(error) = check_snapshot_document(source_document.as_ref(), live) {
                return (session_operation, Err(error));
            }
            if let Some(frame) = &frame_document {
                match session_operation.prepare_frame(&route_key, frame, deadline_ms) {
                    Ok(true) => {}
                    _ => {
                        return (
                            session_operation,
                            Err(BrowserError::StaleSnapshot {
                                reason_code: "frame_document_changed",
                            }),
                        )
                    }
                }
            }
            let result = session_operation.click_point_classified(
                &route_key,
                position,
                document_epoch,
                &source_origin,
                &classification,
                deadline_ms,
                &mut input_dispatched,
            );
            (session_operation, Ok(result))
        })
        .await;
        let (session_operation, drive_result) = match driven {
            Ok(result) => result,
            Err(_) => {
                self.unpin_snapshot(identity, snapshot_id).await;
                return Err(BrowserError::Internal {
                    reason_code: JournalReasonCode::InternalFailure,
                });
            }
        };
        session_operation.finish();
        self.unpin_snapshot(identity, snapshot_id).await;
        let drive_result = self
            .refuse_moved_page(identity, BrowserCapability::ClickPoint, drive_result)
            .await?;
        let mut response = match drive_result {
            Ok(outcome) => self.click_reply(identity, outcome).await,
            Err(crate::browser_session::ClickDriveError::OutsideViewportAfterScroll(refusal)) => {
                return Err(BrowserError::PointOutsideViewport { refusal });
            }
            Err(crate::browser_session::ClickDriveError::Intercepted(detail)) => {
                return Err(BrowserError::Intercepted(detail));
            }
            Err(
                crate::browser_session::ClickDriveError::NoPosition
                | crate::browser_session::ClickDriveError::ClassificationChanged,
            ) => {
                return Err(BrowserError::StaleSnapshot {
                    reason_code: "classification_changed",
                });
            }
            Err(crate::browser_session::ClickDriveError::Navigation(error)) => {
                return Err(map_navigation_drive_error(error));
            }
        };

        response["activated_element"] = activated_element;
        self.finalize(
            identity,
            BrowserCapability::ClickPoint,
            if response["outcome"] == "unsupported_download" {
                Outcome::Denied
            } else {
                Outcome::Success
            },
            response.clone(),
        )
        .await?;
        Ok(response)
    }

    async fn wait_for(
        &self,
        identity: &RouteIdentity,
        args: &Value,
    ) -> Result<Value, BrowserError> {
        let object = self.validate_request(args, &["deadline_ms"]).await?;
        let deadline = optional_integer(object, "deadline_ms", 0, 30_000)?.unwrap_or(30_000);
        let _session_operation = self.reserve(identity, BrowserCapability::WaitFor).await?;
        let mut state = self.state.lock().await;
        if let Some(events) = state.late_events.get_mut(&identity.conversation_key) {
            if let Some(event) = events.pop_front() {
                let outcome = event.outcome();
                let remedy = event.remedy();
                let detail = match event {
                    LateEvent::NavigationPolicyRejected { reason_code } => {
                        json!({"reason_code":reason_code})
                    }
                    LateEvent::AuthorizationDenied { reason } => json!({"reason":reason}),
                    _ => json!({}),
                };
                return Ok(
                    json!({"outcome":outcome,"remedy":remedy,"detail":detail,"url_final":Value::Null,"lifecycle":[],"inflight_count":0}),
                );
            }
        }
        let context = state
            .contexts
            .get_mut(&identity.conversation_key)
            .ok_or(BrowserError::NoSession)?;
        if context.ended {
            return Err(BrowserError::NoSession);
        }
        let now = Instant::now();
        if context.tracker.poll_settlement(now) {
            return Ok(
                json!({"outcome":"ok","url_final":context.tracker.url_final,"lifecycle":context.tracker.lifecycle,"inflight_count":context.tracker.inflight_count}),
            );
        }
        let _ = deadline;
        Err(BrowserError::NotSettled {
            url_final: context.tracker.url_final.clone(),
            lifecycle: context.tracker.lifecycle.clone(),
            inflight_count: context.tracker.inflight_count,
            deadline_ms: deadline,
        })
    }

    /// Install a coherent screenshot produced by the browser screenshot adapter.
    /// This is the only path that retains clickable image state.
    pub async fn retain_screenshot(
        &self,
        identity: &RouteIdentity,
        payload: ScreenshotPayload,
        before: ViewportObservation,
        after: ViewportObservation,
        invalidation_observed: bool,
        // The document the adapter captured; `None` makes the screenshot
        // unusable for click_point, which requires the page to still show it.
        source_document: Option<CommittedDocument>,
    ) -> Result<Value, BrowserError> {
        let _lane = self.lane(&identity.conversation_key).await;
        self.retain_screenshot_inner(
            identity,
            payload,
            before,
            after,
            invalidation_observed,
            source_document,
            Vec::new(),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn retain_screenshot_inner(
        &self,
        identity: &RouteIdentity,
        payload: ScreenshotPayload,
        before: ViewportObservation,
        after: ViewportObservation,
        invalidation_observed: bool,
        // The document the capture was authorized against; its URL becomes
        // the source. `None` falls back to the tracked page, as for text
        // snapshots.
        source_document: Option<CommittedDocument>,
        frame_documents: Vec<crate::snapshot_store::FrameDocument>,
    ) -> Result<Value, BrowserError> {
        let coherent = capture_screenshot(before, payload, after, invalidation_observed)
            .map_err(map_coordinate_error)?;
        let mut state = self.state.lock().await;
        let context = state
            .contexts
            .get_mut(&identity.conversation_key)
            .ok_or(BrowserError::NoSession)?;
        let id = context.snapshot_id(SnapshotKind::Screenshot);
        let source_origin = source_document
            .as_ref()
            .map(|document| document.url.clone())
            .unwrap_or_else(|| {
                context
                    .tracker
                    .url_final
                    .clone()
                    .unwrap_or_else(|| "null".into())
            });
        let mut snapshot = coherent.into_snapshot(id.clone(), source_origin);
        snapshot.source_document = source_document;
        snapshot.frame_documents = frame_documents;
        let result = json!({"outcome":"ok","snapshot_id":snapshot.snapshot_id,"document_epoch":snapshot.document_epoch,"source_origin":snapshot.source_origin,"image":{"mime":"image/png","data_b64":snapshot.image_png_b64,"width_px":snapshot.image_width_px,"height_px":snapshot.image_height_px},"image_width_px":snapshot.image_width_px,"image_height_px":snapshot.image_height_px,"input_rect":{"x_input_css":snapshot.input_rect.x_input_css,"y_input_css":snapshot.input_rect.y_input_css,"width_input_css":snapshot.input_rect.width_input_css,"height_input_css":snapshot.input_rect.height_input_css},"device_scale_factor":snapshot.device_scale_factor,"visual_viewport_scale":snapshot.visual_viewport_scale});
        context
            .snapshots
            .retain_screenshot(snapshot)
            .map_err(map_snapshot_error)?;
        context.refs.prune_shown(&context.snapshots);
        Ok(result)
    }

    pub async fn replace_document(
        &self,
        identity: &RouteIdentity,
        transition: DocumentTransition,
    ) -> Result<u64, BrowserError> {
        let _lane = self.lane(&identity.conversation_key).await;
        let mut state = self.state.lock().await;
        let context = state
            .contexts
            .get_mut(&identity.conversation_key)
            .ok_or(BrowserError::NoSession)?;
        let epoch = context
            .epoch
            .replace(transition)
            .map_err(map_snapshot_error)?;
        context.snapshots.invalidate_before(epoch);
        context.refs.prune_shown(&context.snapshots);
        Ok(epoch)
    }

    pub async fn same_document_url(
        &self,
        identity: &RouteIdentity,
        url: impl Into<String>,
        change: SameDocumentChange,
    ) -> Result<(), BrowserError> {
        let _lane = self.lane(&identity.conversation_key).await;
        let mut state = self.state.lock().await;
        let context = state
            .contexts
            .get_mut(&identity.conversation_key)
            .ok_or(BrowserError::NoSession)?;
        context.tracker.url_final = Some(url.into());
        let _ = context.epoch.same_document(change);
        Ok(())
    }

    pub async fn poll_settlement(
        &self,
        identity: &RouteIdentity,
        now: Instant,
    ) -> Result<bool, BrowserError> {
        let _lane = self.lane(&identity.conversation_key).await;
        let mut state = self.state.lock().await;
        Ok(state
            .contexts
            .get_mut(&identity.conversation_key)
            .ok_or(BrowserError::NoSession)?
            .tracker
            .poll_settlement(now))
    }

    pub async fn observe_request_started(
        &self,
        identity: &RouteIdentity,
    ) -> Result<(), BrowserError> {
        let _lane = self.lane(&identity.conversation_key).await;
        let mut state = self.state.lock().await;
        state
            .contexts
            .get_mut(&identity.conversation_key)
            .ok_or(BrowserError::NoSession)?
            .tracker
            .request_started();
        Ok(())
    }

    pub async fn observe_request_finished(
        &self,
        identity: &RouteIdentity,
        now: Instant,
    ) -> Result<(), BrowserError> {
        let _lane = self.lane(&identity.conversation_key).await;
        let mut state = self.state.lock().await;
        state
            .contexts
            .get_mut(&identity.conversation_key)
            .ok_or(BrowserError::NoSession)?
            .tracker
            .request_finished(now);
        Ok(())
    }

    pub async fn observe_load(
        &self,
        identity: &RouteIdentity,
        now: Instant,
    ) -> Result<(), BrowserError> {
        let _lane = self.lane(&identity.conversation_key).await;
        let mut state = self.state.lock().await;
        state
            .contexts
            .get_mut(&identity.conversation_key)
            .ok_or(BrowserError::NoSession)?
            .tracker
            .load(now);
        Ok(())
    }

    pub async fn record_download(&self, identity: &RouteIdentity) -> Result<(), BrowserError> {
        let _lane = self.lane(&identity.conversation_key).await;
        let mut state = self.state.lock().await;
        state
            .contexts
            .get_mut(&identity.conversation_key)
            .ok_or(BrowserError::NoSession)?
            .tracker
            .token("download_blocked");
        state
            .late_events
            .entry(identity.conversation_key.clone())
            .or_default()
            .push_back(LateEvent::DownloadBlocked);
        Ok(())
    }

    pub async fn record_dialog(&self, identity: &RouteIdentity) -> Result<(), BrowserError> {
        let _lane = self.lane(&identity.conversation_key).await;
        let mut state = self.state.lock().await;
        state
            .contexts
            .get_mut(&identity.conversation_key)
            .ok_or(BrowserError::NoSession)?
            .tracker
            .token("js_dialog_dismissed");
        state
            .late_events
            .entry(identity.conversation_key.clone())
            .or_default()
            .push_back(LateEvent::JsDialogDismissed);
        Ok(())
    }

    /// Record-only policy events never enter the caller-visible FIFO.
    pub async fn record_subresource_policy_event(&self, _identity: &RouteIdentity) {}
}

fn severity_schema() -> Value {
    json!({"type":"object","properties":{"tier":{"type":"integer","minimum":1,"maximum":5},"credential":{"type":"boolean"},"financial":{"type":"boolean"}},"required":["tier","credential","financial"],"additionalProperties":false})
}

struct BrowserToolDefinition {
    name: &'static str,
    description: &'static str,
    request_schema: Value,
    result_schema: Value,
}

mod typing;

fn browser_tool_definitions() -> Vec<BrowserToolDefinition> {
    vec![
        BrowserToolDefinition {
            name: NAVIGATE,
            description: "Navigate managed Chromium through the enforcing connector. Set read_page to return a bounded snapshot of the landing page.",
            request_schema: json!({"type":"object","properties":{"url":{"type":"string"},"intent":{"type":"string"},"wait":{"type":"string","enum":["settle","none"]},"severity":severity_schema(),"read_page":{"type":"boolean","default":false,"description":"Return the landing page's outline in state_text, as snapshot does."},"max_bytes":{"type":"integer","minimum":1,"maximum":262144,"default":DEFAULT_READ_PAGE_MAX_BYTES,"description":"Maximum bytes of returned page text; this bounds returned text, not the page observed."}},"required":["url","intent","severity"],"additionalProperties":false}),
            result_schema: navigate_result_schema(),
        },
        BrowserToolDefinition {
            name: SNAPSHOT,
            description: "Read the page as plain text in state_text: an outline of its landmarks by default, main content first; zoom names one ref to print that element's whole subtree. Use ax or dom_full only when something is missing.",
            request_schema: json!({"type":"object","properties":{"mode":{"type":"string","enum":["actionable","ax","dom_full"],"default":"actionable"},"text_filter":{"type":"string","maxLength":4096,"description":"Keep label/value matches beneath labelled ancestors. Default mode only."},"role_filter":{"type":"array","items":{"type":"string","minLength":1,"maxLength":128},"minItems":1,"maxItems":16,"description":"Keep matching roles, case-insensitively (AXButton, Button or button). Default mode only."},"zoom":{"type":"string","description":"A previously printed ref; prints that element's whole subtree instead of the outline while it exists on the same page. Default mode only."},"max_bytes":{"type":"integer","minimum":1,"maximum":262144,"default":65536,"description":"Cap on state_text bytes. When cut, main content is kept before navigation and the last line says what was cut."}},"additionalProperties":false}),
            result_schema: snapshot_result_schema(),
        },
        BrowserToolDefinition {
            name: TYPE,
            description: "Type into a previously printed ref; clear_first replaces its contents. Credential and payment fields require present instead.",
            request_schema: json!({"type":"object","properties":{"ref":{"type":"string"},"snapshot_id":{"type":"string","description":"Optional retained snapshot that showed this ref; otherwise use its most recent shown snapshot."},"text":{"type":"string","maxLength":10000},"clear_first":{"type":"boolean","default":false}},"required":["ref","text"],"additionalProperties":false}),
            result_schema: reply_schema(json!({"characters_dispatched":integer_schema()}), &[]),
        },
        BrowserToolDefinition {
            name: CLICK,
            description: "Click a retained structured reference. The reply's navigation reports what the click did to the page: none_observed (within navigation_window_ms), same_document, not_committed, or main_frame with url_final, lifecycle, and landing_origin_granted, which is false when a read of the landing page would be refused.",
            request_schema: json!({"type":"object","properties":{"ref":{"type":"string"},"snapshot_id":{"type":"string"},"intent":{"type":"string"},"severity":severity_schema()},"required":["ref","snapshot_id","intent","severity"],"additionalProperties":false}),
            result_schema: click_result_schema(),
        },
        BrowserToolDefinition {
            name: SCREENSHOT,
            description: "Capture the current visual viewport as PNG base64; max_bytes guards context size but does not reduce vision-token cost because vision APIs may downscale independently.",
            request_schema: json!({"type":"object","properties":{"max_bytes":{"type":"integer","minimum":1,"maximum":MAX_ENCODED_PNG_BYTES}},"additionalProperties":false}),
            result_schema: screenshot_result_schema(),
        },
        BrowserToolDefinition {
            name: SCROLL,
            description: "Scroll a previously printed ref into view, or scroll by direction and amount (CSS pixels, default 600). Tier 1; never fronts the window. Choose ref or direction, not both. Unsupported on the user-browser target.",
            request_schema: json!({"type":"object","properties":{
                "ref":{"type":"string","description":"A previously printed ref to bring into view. Do not combine with direction or amount."},
                "direction":{"type":"string","enum":["up","down","left","right"],"description":"Use instead of ref."},
                "amount":{"type":"integer","minimum":1,"maximum":10000,"default":600,"description":"CSS pixels; direction only."}
            },"additionalProperties":false}),
            result_schema: reply_schema(json!({"scroll_dispatched":boolean_schema()}), &[]),
        },
        BrowserToolDefinition {
            name: CLICK_POINT,
            description: "Click a retained screenshot pixel. Coordinates address the image this module declared; pass its image_width_px and image_height_px so a coordinate taken from a resized copy is refused rather than mis-clicked. The reply reports navigation as browser.click does.",
            request_schema: json!({"type":"object","properties":{"snapshot_id":{"type":"string"},"x_px":{"type":"integer"},"y_px":{"type":"integer"},"image_width_px":{"type":"integer"},"image_height_px":{"type":"integer"},"intent":{"type":"string"},"severity":severity_schema()},"required":["snapshot_id","x_px","y_px","image_width_px","image_height_px","intent","severity"],"additionalProperties":false}),
            result_schema: click_point_result_schema(),
        },
        BrowserToolDefinition {
            name: WAIT_FOR,
            description: "Wait for browser settlement or a queued browser event.",
            request_schema: json!({"type":"object","properties":{"deadline_ms":{"type":"integer","minimum":0,"maximum":30000}},"additionalProperties":false}),
            result_schema: wait_for_result_schema(),
        },
        BrowserToolDefinition {
            name: crate::browser_session::BROWSER_LAUNCH,
            description: "Launch the route-owned browser session.",
            request_schema: json!({"type":"object","properties":{},"additionalProperties":false}),
            result_schema: browser_launch_result_schema(),
        },
        BrowserToolDefinition {
            name: crate::browser_session::BROWSER_STATUS,
            description: "Report the route-owned browser session state.",
            request_schema: json!({"type":"object","properties":{},"additionalProperties":false}),
            result_schema: browser_status_result_schema(),
        },
        // Served on the management surface, never advertised as a tool: it is
        // listed here only so its reply passes the same closed-schema boundary.
        BrowserToolDefinition {
            name: crate::management::IMPORT_LOGIN,
            description: "Import an existing login with consent, reopening an idle browser session.",
            request_schema: json!({"type":"object","properties":{"origin":{"type":"string"}},"required":["origin"],"additionalProperties":false}),
            result_schema: crate::login_import::reply_schema(browser_launch_result_schema()),
        },
        BrowserToolDefinition {
            name: crate::management::PRESENT,
            description: "Hand the route-owned browser to the person for login.",
            request_schema: json!({"type":"object","properties":{"origin":{"type":"string"}},"required":["origin"],"additionalProperties":false}),
            result_schema: json!({"type":"object","required":["outcome"],"additionalProperties":false,"properties":{
                "outcome":{"type":"string","enum":["presented","login_pending","login_observed","handoff_expired","handoff_interrupted","closed_by_caller","no_session","origin_mismatch","handoff_open","present_failed","internal_failure"]},
                "origin":{"type":"string"},"expires_in_ms":{"type":"integer"},
                "current_origin":{"type":"string"},"remedy":{"type":"string"},"error_text":{"type":"string"}
            }}),
        },
        BrowserToolDefinition {
            name: crate::management::RESUME,
            description: "Take back a login handoff and report its ending.",
            request_schema: json!({"type":"object","properties":{},"additionalProperties":false}),
            result_schema: json!({"type":"object","required":["outcome"],"additionalProperties":false,"properties":{
                "outcome":{"type":"string","enum":["resumed","no_handoff","internal_failure"]},
                "handoff":{"type":"string","enum":["login_observed","expired","closed_by_caller"]},
                "origin":{"type":"string"},"remedy":{"type":"string"}
            }}),
        },
        // Served on the management surface and reached as the flat tool's
        // revoke_access action; listed for the same closed-schema boundary.
        BrowserToolDefinition {
            name: crate::management::REVOKE_ACCESS,
            description: "Remove this agent's own standing browser access: every standing grant, or the one for origin.",
            request_schema: json!({"type":"object","properties":{"origin":{"type":"string"}},"additionalProperties":false}),
            result_schema: revoke_access_result_schema(),
        },
        BrowserToolDefinition {
            name: crate::management::WOULD_ASK,
            description: "Check standing per-agent grants without elicitation.",
            request_schema: json!({"type":"object"}),
            result_schema: crate::management::would_ask_result_schema(),
        },
        BrowserToolDefinition {
            name: crate::management::CAPTURE_LOGIN,
            description: "Capture a fresh login in a throwaway browser for the operator to store.",
            request_schema: crate::login_capture::request_schema(),
            result_schema: crate::login_capture::reply_schema(),
        },
        BrowserToolDefinition {
            name: crate::browser_session::BROWSER_CLOSE,
            description: "Close and reap the route-owned browser session.",
            request_schema: json!({"type":"object","properties":{"browser_session_id":{"type":"string","minLength":1}},"required":["browser_session_id"],"additionalProperties":false}),
            result_schema: browser_close_result_schema(),
        },
    ]
    .into_iter()
    .map(|mut definition| {
        definition.result_schema = with_bounded_call_results(definition.result_schema);
        definition
    })
    .collect()
}

pub fn tool_definitions() -> Vec<(&'static str, &'static str, Value)> {
    browser_tool_definitions()
        .into_iter()
        .filter(|definition| {
            !matches!(
                definition.name,
                crate::management::PRESENT | crate::management::RESUME
            )
        })
        .filter(|definition| BrowserCapability::parse(definition.name).is_some())
        .map(|definition| {
            (
                definition.name,
                definition.description,
                definition.request_schema,
            )
        })
        .collect()
}

fn string_schema() -> Value {
    json!({"type":"string"})
}

fn nullable_string_schema() -> Value {
    json!({"type":["null","string"]})
}

fn integer_schema() -> Value {
    json!({"type":"integer"})
}

fn number_schema() -> Value {
    json!({"type":"number"})
}

fn boolean_schema() -> Value {
    json!({"type":"boolean"})
}

fn string_array_schema() -> Value {
    json!({"type":"array","items":string_schema()})
}

fn closed_object(properties: Value, required: &[&str]) -> Value {
    json!({
        "type":"object",
        "properties":properties,
        "required":required,
        "additionalProperties":false,
    })
}

fn context_result_schema() -> Value {
    closed_object(
        json!({
            "profile_uuid":nullable_string_schema(),
            "profile_name":nullable_string_schema(),
            "session_kind_effective":string_schema(),
            "profile_disposition":string_schema(),
        }),
        &[
            "profile_uuid",
            "profile_name",
            "session_kind_effective",
            "profile_disposition",
        ],
    )
}

/// Severity as it appears in a reply. Distinct from the request-side schema
/// because the result-schema vocabulary has no numeric bounds keywords.
fn severity_result_schema() -> Value {
    closed_object(
        json!({"tier":integer_schema(),"credential":boolean_schema(),"financial":boolean_schema()}),
        &["tier", "credential", "financial"],
    )
}

fn refusal_detail_schema() -> Value {
    closed_object(
        json!({
            "field":string_schema(),
            "decision":string_schema(),
            "reason_code":string_schema(),
            "navigation_sent":boolean_schema(),
            "step":string_schema(),
            "command_sent":boolean_schema(),
            "reason":string_schema(),
            "grant":string_schema(),
            "grant_label":string_schema(),
            "attempted_origin":string_schema(),
            "granted_origins":string_array_schema(),
            "authorized_origin":string_schema(),
            "live_origin":string_schema(),
            "snapshot_origin":string_schema(),
            "error_text":string_schema(),
            "ref":string_schema(),
            "candidates":integer_schema(),
            "bytes":integer_schema(),
            "bound_bytes":integer_schema(),
            "missing_hazard":string_schema(),
            "required":severity_result_schema(),
            "granted_ceilings":json!({"type":"array","items":severity_result_schema()}),
            "grant_request":closed_object(json!({
                "origins":string_array_schema(),
                "severity_tier":integer_schema(),
                "hazards":string_array_schema(),
            }), &["origins", "severity_tier", "hazards"]),
            "hit_backend_node_id":integer_schema(),
            "hit_role":nullable_string_schema(),
            "hit_name":nullable_string_schema(),
            "hit_inside_target":json!({"type":["boolean","null"]}),
            "classification_unavailable":string_schema(),
            "classification_unavailable_facts":closed_object(json!({
                "index":integer_schema(),
                "field":string_schema(),
                "node_id":integer_schema(),
                "backend_node_id":integer_schema(),
                "length":integer_schema(),
                "position":integer_schema(),
                "classifier_error":string_schema(),
            }), &[]),
            "url_final":nullable_string_schema(),
            "lifecycle":string_array_schema(),
            "inflight_count":integer_schema(),
            "deadline_ms":integer_schema(),
            "point":closed_object(json!({"x_css":number_schema(),"y_css":number_schema()}), &["x_css", "y_css"]),
            "viewport":closed_object(json!({"x_css":number_schema(),"y_css":number_schema(),"width_css":number_schema(),"height_css":number_schema()}), &["x_css", "y_css", "width_css", "height_css"]),
        }),
        &[],
    )
}

fn bounded_call_reply_schema() -> Value {
    closed_object(
        json!({
            "outcome":enum_schema(&[
                "action_deadline_exceeded", "dispatch_outcome_unknown",
                "target_busy", "blocking_capacity_exhausted",
            ]),
            "detail":closed_object(json!({
                "dispatched":boolean_schema(),
                "step":enum_schema(&["admission", "queue", "consent", "preflight", "dispatch", "release"]),
                "call":string_schema(),
                "held_state":enum_schema(&["none_held", "released", "unknown"]),
                "reason":{
                    "type":"string",
                    "description":"Bounded-call causes include action_deadline_exceeded, cancelled, route_closed, module_draining and held_input_unconfirmed. Other refusal reasons remain free-form."
                },
            }), &[]),
            "effect_status":enum_schema(&["effect_observed", "no_effect_observed", "effect_indeterminate"]),
            "remedy":string_schema(),
            "context":context_result_schema(),
        }),
        &["outcome", "detail"],
    )
}

fn with_bounded_call_results(legacy_schema: Value) -> Value {
    // Deadline, unknown-dispatch, busy-target and capacity replies can end a call
    // before context resolution or an operation-specific result exists. Their
    // separate branch permits only those four outcomes and six execution phases,
    // without relaxing legacy required fields or legacy CDP method step strings.
    json!({"anyOf": [legacy_schema, bounded_call_reply_schema()]})
}

fn text_snapshot_properties() -> Value {
    json!({
        "mode":{"type":"string","enum":["actionable","ax","dom_full"]},
        "omitted":closed_object(json!({"state_text_bytes":integer_schema(),"state_text_lines":integer_schema(),"source_origin":boolean_schema()}), &["state_text_bytes","state_text_lines","source_origin"]),
        "snapshot_id":string_schema(),
        "document_epoch":integer_schema(),
        "source_origin":string_schema(),
        "content_schema":string_schema(),
        "truncated":boolean_schema(),
        "refs_truncated":boolean_schema(),
        (state_text::STATE_TEXT_FIELD):string_schema(),
    })
}

fn screenshot_properties() -> Value {
    json!({
        "snapshot_id":string_schema(),
        "document_epoch":integer_schema(),
        "source_origin":string_schema(),
        "image":closed_object(json!({
            "mime":string_schema(),
            "data_b64":string_schema(),
            "width_px":integer_schema(),
            "height_px":integer_schema(),
        }), &["mime", "data_b64", "width_px", "height_px"]),
        "image_width_px":integer_schema(),
        "image_height_px":integer_schema(),
        "input_rect":closed_object(json!({"x_input_css":number_schema(),"y_input_css":number_schema(),"width_input_css":number_schema(),"height_input_css":number_schema()}), &["x_input_css", "y_input_css", "width_input_css", "height_input_css"]),
        "device_scale_factor":number_schema(),
        "visual_viewport_scale":number_schema(),
    })
}

fn browser_result_outcome_schema() -> Value {
    json!({"type":"string","enum":[
        "ok",
        "javascript_dialog_dismissed",
        "unsupported_download",
        "unsupported_js_dialog",
        "invalid_request",
        "no_session",
            "browser_launch_pending",
            "human_in_control",
            "stale_snapshot",
        "ref_not_found",
        "ref_ambiguous",
        "classification_unavailable",
        "element_intercepted",
        "outside_viewport_after_scroll",
        "point_outside_viewport",
        "invalid_coordinates",
        "image_too_large",
        "authorization_denied",
        "consent_pending",
        "consent_unavailable",
        "hazard_not_disclosed",
        "navigation_policy_rejected",
        "navigation_failed",
        "page_navigated_during_read",
        "not_settled",
        "type_not_ready",
        "navigate_not_ready",
        "command_timeout",
        "browser_crashed",
        "internal_error",
        "internal_failure"
    ]})
}

fn reply_schema(mut properties: Value, required: &[&str]) -> Value {
    let properties = properties
        .as_object_mut()
        .expect("browser result properties are objects");
    properties.insert("outcome".into(), browser_result_outcome_schema());
    properties.insert("browser".into(), enum_schema(&["user"]));
    properties.insert("remedy".into(), string_schema());
    properties.insert("detail".into(), refusal_detail_schema());
    properties.insert("context".into(), context_result_schema());
    properties.insert("origin".into(), string_schema());
    properties.insert("expires_in_ms".into(), integer_schema());
    properties.insert("ask_id".into(), string_schema());
    properties.insert("origins".into(), string_array_schema());
    properties.insert("hazards".into(), string_array_schema());
    properties.insert(
        "severity_ceiling".into(),
        closed_object(
            json!({
                "tier":integer_schema(), "credential":boolean_schema(),
                "financial":boolean_schema(), "name":string_schema(),
            }),
            &["tier", "credential", "financial", "name"],
        ),
    );
    properties.insert(
        "stage".into(),
        enum_schema(&[crate::browser_session::BROWSER_SESSION_LOCK_STAGE]),
    );
    let mut required = required.to_vec();
    required.extend(["outcome", "context"]);
    closed_object(properties.clone().into(), &required)
}

fn embedded_read_page_schema() -> Value {
    let properties = text_snapshot_properties();
    let properties = properties
        .as_object()
        .expect("text snapshot properties are objects")
        .clone();
    let mut properties = properties;
    properties.insert("outcome".into(), browser_result_outcome_schema());
    properties.insert("remedy".into(), string_schema());
    properties.insert("detail".into(), refusal_detail_schema());
    closed_object(properties.into(), &["outcome"])
}

fn navigation_lifecycle_schema() -> Value {
    closed_object(
        json!({
            "events":string_array_schema(),
            "loaded":boolean_schema(),
            "settled":boolean_schema(),
        }),
        &["events", "loaded", "settled"],
    )
}

fn navigate_result_schema() -> Value {
    reply_schema(
        json!({
            "url_final":nullable_string_schema(),
            "lifecycle":navigation_lifecycle_schema(),
            "http_status":integer_schema(),
            "challenge":closed_object(json!({"vendor":string_schema(),"evidence":string_schema()}), &["vendor", "evidence"]),
            (state_text::STATE_TEXT_FIELD):string_schema(),
            "read_page":embedded_read_page_schema(),
        }),
        &[],
    )
}

fn snapshot_result_schema() -> Value {
    reply_schema(text_snapshot_properties(), &[])
}

fn click_result_schema() -> Value {
    reply_schema(
        json!({
            "navigation":enum_schema(&["none_observed", "same_document", "not_committed", "main_frame"]),
            "navigation_window_ms":integer_schema(),
            "activated_element":closed_object(json!({"identity":string_schema(),"kind":string_schema()}), &["identity","kind"]),
            "url_final":nullable_string_schema(),
            "lifecycle":navigation_lifecycle_schema(),
            "http_status":integer_schema(),
            "challenge":closed_object(json!({"vendor":string_schema(),"evidence":string_schema()}), &["vendor", "evidence"]),
            "landing_origin":string_schema(),
            "landing_origin_granted":boolean_schema(),
            "dialogs":json!({"type":"array","items":closed_object(json!({"dialog_type":string_schema(),"response":string_schema()}), &["dialog_type", "response"])}),
        }),
        &[],
    )
}

fn screenshot_result_schema() -> Value {
    reply_schema(screenshot_properties(), &[])
}

fn click_point_result_schema() -> Value {
    click_result_schema()
}

fn wait_for_result_schema() -> Value {
    reply_schema(
        json!({
            "url_final":nullable_string_schema(),
            "lifecycle":string_array_schema(),
            "inflight_count":integer_schema(),
        }),
        &[],
    )
}

fn enum_schema(values: &[&str]) -> Value {
    json!({"type":"string","enum":values})
}

/// The reply of `browser.revoke_access`: how many standing rows it revoked,
/// and why none were when the store could not be read or written or the
/// route's agent is not attested.
fn revoke_access_result_schema() -> Value {
    closed_object(
        json!({
            "outcome":enum_schema(&[
                "revoked",
                "nothing_to_revoke",
                "store_unavailable",
                "revoke_failed",
                "agent_not_attested",
            ]),
            "revoked":integer_schema(),
            "reason":string_schema(),
            "remedy":string_schema(),
        }),
        &["outcome", "revoked"],
    )
}

fn browser_lease_result_schema() -> Value {
    closed_object(
        json!({
            "idle_expires_at":string_schema(),
            "idle_timeout_ms":integer_schema(),
        }),
        &["idle_expires_at", "idle_timeout_ms"],
    )
}

fn invalid_request_detail_result_schema() -> Value {
    closed_object(
        json!({
            "field":string_schema(),
            "reason_code":string_schema(),
        }),
        &["field", "reason_code"],
    )
}

fn browser_control_result_schema(outcomes: &[&str], mut properties: Value) -> Value {
    let properties = properties
        .as_object_mut()
        .expect("browser control result properties are objects");
    // Every control operation can be refused at admission, before its own
    // outcomes apply, so the refusal belongs to all three vocabularies rather
    // than to whichever of them first happened to be exercised.
    let mut outcomes = outcomes.to_vec();
    outcomes.push("authorization_denied");
    outcomes.push("consent_unavailable");
    properties.insert("outcome".into(), enum_schema(&outcomes));
    properties.insert("browser".into(), enum_schema(&["user"]));
    let detail = match properties.remove("detail") {
        Some(detail) => json!({"anyOf": [invalid_request_detail_result_schema(), detail]}),
        None => invalid_request_detail_result_schema(),
    };
    let cleanup_detail = closed_object(
        json!({
            "step": enum_schema(&["graceful_close_request", "wait_for_exit", "forced_termination", "reap_wait"]),
            "error_kind": string_schema(),
        }),
        &["step"],
    );
    properties.insert("detail".into(), json!({"anyOf": [detail, cleanup_detail]}));
    properties.insert("remedy".into(), string_schema());
    // `browser.launch` already carries a free-form `reason` for its own
    // refusals; the other two get the closed admission vocabulary.
    properties.entry("reason").or_insert_with(|| {
        let codes: Vec<&str> = cerebellum_core::identity::ControlOperationRefusal::ALL
            .iter()
            .map(|refusal| refusal.reason_code())
            .collect();
        enum_schema(&codes)
    });
    closed_object(properties.clone().into(), &["outcome"])
}

fn browser_launch_result_schema() -> Value {
    browser_control_result_schema(
        &[
            "launched",
            "browser_session_exists",
            "no_profile",
            "executable_missing",
            "browser_launch_unsupported",
            "internal_failure",
            "launch_cancelled",
            "cleanup_failure",
            "invalid_request",
            // Refusals from profile custody and preparation, rendered by
            // `BrowserLaunchOutcome::as_json` or by the launch service while it
            // opens profile storage. Each carries a reason or remedy the caller
            // needs; left undeclared, the reply boundary replaced them with a
            // schema violation that told the caller nothing.
            "profile_busy",
            "resource_busy",
            // The profile is held by startup recovery for a browser from
            // before a restart that could not be proven gone. `reason` names
            // why and `remedy` names the operator's clear.
            "profile_recovery_pending",
            "profile_grant_required",
            "profile_registry_untrusted_root",
            "profile_storage_unavailable",
            "custody_locks_unavailable",
            // Refusals from the executable identity check and the platform
            // launcher, before and after the browser process is spawned.
            "identity_unverifiable",
            "executable_identity_mismatch",
            "launch_refused",
            "responsibility_disclaim_unavailable",
            // The browser exited or went silent before its handshake, and this
            // layer cannot tell why.
            "profile_startup_indeterminate",
        ],
        json!({
            "browser_session_id":string_schema(),
            "profile_disposition":enum_schema(&["none", "durable", "disposable"]),
            "platform":string_schema(),
            "expected_path":string_schema(),
            "reason":string_schema(),
            "executable_identity_checkpoints":enum_schema(&["before_spawn_and_after_exec", "after_exec_only"]),
            "lease":browser_lease_result_schema(),
            "stage":string_schema(),
            "reason_code":string_schema(),
            // The custody holder currently owning the profile. Minted by the
            // custody lock, never a profile UUID or path.
            "holder_id":string_schema(),
            "detail":resource_busy_detail_schema(),
            "rollback":enum_schema(&["rollback_opened"]),
            "pipe":enum_schema(&["command", "response", "cdp"]),
            "claim_kind":enum_schema(&["code_signed", "image_digest"]),
            "expected_identity":string_schema(),
            "observed_identity":string_schema(),
            "cause":startup_cause_schema(),
            "ambiguity":startup_ambiguity_schema(),
            "possible_reasons":startup_possible_reasons_schema(),
            // When the browser failed to start AND finalizing its launch
            // journal entry then failed too, the reply's stage names the
            // journal step and `primary` preserves the startup failure.
            "primary":closed_object(
                json!({
                    "outcome":enum_schema(&["profile_startup_indeterminate"]),
                    "cause":startup_cause_schema(),
                    "ambiguity":startup_ambiguity_schema(),
                    "possible_reasons":startup_possible_reasons_schema(),
                }),
                &["outcome", "cause", "ambiguity", "possible_reasons"],
            ),
        }),
    )
}

fn startup_cause_schema() -> Value {
    enum_schema(&["child_exit", "pipe_closed", "deadline_expired"])
}

fn startup_ambiguity_schema() -> Value {
    enum_schema(&["indeterminate_startup_failure"])
}

fn startup_possible_reasons_schema() -> Value {
    json!({
        "type":"array",
        "items":enum_schema(&[
            "external_profile_holder",
            "profile_unopenable_or_corrupt",
            "browser_startup_failure",
            "invalid_browser_invocation",
            "platform_or_sandbox_denial",
        ]),
    })
}

fn browser_status_result_schema() -> Value {
    browser_control_result_schema(
        &[
            "ready",
            "no_session",
            "terminal",
            "cleanup_failure",
            "durable_state_at_risk",
            "invalid_request",
            "internal_failure",
        ],
        json!({
            "browser_session_id":string_schema(),
            "profile_disposition":enum_schema(&["durable", "disposable"]),
            "lease":browser_lease_result_schema(),
            "stage":enum_schema(&["reap", "record_terminalization", "custody_release", "disposable_delete", "crash_reports_delete", "custody_held", crate::browser_session::BROWSER_SESSION_LOCK_STAGE]),
            "terminal_outcome":enum_schema(&["closed", "browser_crashed", "connector_failure", "cdp_failure", "idle_expired", "route_unbound", "scope_revoked", "module_shutdown", "cleanup_failure", "startup_indeterminate"]),
            "failed_signals":string_array_schema(),
        }),
    )
}

fn browser_close_result_schema() -> Value {
    browser_control_result_schema(
        &[
            "closed",
            "browser_crashed",
            "connector_failure",
            "cdp_failure",
            "idle_expired",
            "route_unbound",
            "scope_revoked",
            "module_shutdown",
            "cleanup_failure",
            "startup_indeterminate",
            "browser_session_not_found",
            "durable_state_at_risk",
            "invalid_request",
            "internal_failure",
        ],
        json!({
            "browser_session_id":string_schema(),
            "stage":enum_schema(&["reap", "record_terminalization", "custody_release", "disposable_delete", "crash_reports_delete", "custody_held", crate::browser_session::BROWSER_SESSION_LOCK_STAGE]),
            "failed_signals":string_array_schema(),
        }),
    )
}

fn schema_types(
    schema: &Map<String, Value>,
    path: &str,
) -> Result<Vec<String>, CapabilityResultValidationError> {
    let values = match schema.get("type") {
        Some(Value::String(value)) => vec![value.clone()],
        Some(Value::Array(values)) => values
            .iter()
            .map(Value::as_str)
            .map(|value| value.map(str::to_string))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| {
                CapabilityResultValidationError::MalformedArtifact(format!(
                    "{path}.type contains a non-string"
                ))
            })?,
        _ => {
            return Err(CapabilityResultValidationError::MalformedArtifact(format!(
                "{path} result schema has no string or string-array type"
            )))
        }
    };
    if values.is_empty()
        || values.iter().any(|value| {
            !matches!(
                value.as_str(),
                "array" | "boolean" | "integer" | "null" | "number" | "object" | "string"
            )
        })
        || values
            .iter()
            .any(|value| value == "array" || value == "object")
            && values.len() != 1
            && !(values.len() == 2
                && values.iter().any(|value| value == "object")
                && values.iter().any(|value| value == "null"))
    {
        return Err(CapabilityResultValidationError::MalformedArtifact(format!(
            "{path} has unsupported or incompatible result types"
        )));
    }
    Ok(values)
}

fn value_has_type(value: &Value, schema_type: &str) -> bool {
    match schema_type {
        "array" => value.is_array(),
        "boolean" => value.is_boolean(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "null" => value.is_null(),
        "number" => value.is_number(),
        "object" => value.is_object(),
        "string" => value.is_string(),
        _ => false,
    }
}

fn validate_runtime_result_schema(
    schema: &Value,
    path: &str,
) -> Result<(), CapabilityResultValidationError> {
    let object = schema.as_object().ok_or_else(|| {
        CapabilityResultValidationError::MalformedArtifact(format!(
            "{path} result schema is not an object"
        ))
    })?;
    if let Some(alternatives) = object.get("anyOf") {
        if object.len() != 1 {
            return Err(CapabilityResultValidationError::MalformedArtifact(format!(
                "{path}.anyOf cannot be combined with other keywords"
            )));
        }
        let alternatives = alternatives
            .as_array()
            .filter(|items| !items.is_empty())
            .ok_or_else(|| {
                CapabilityResultValidationError::MalformedArtifact(format!(
                    "{path}.anyOf must be a nonempty array"
                ))
            })?;
        for (index, alternative) in alternatives.iter().enumerate() {
            validate_runtime_result_schema(alternative, &format!("{path}.anyOf[{index}]"))?;
        }
        return Ok(());
    }
    for keyword in object.keys() {
        if !matches!(
            keyword.as_str(),
            "additionalProperties"
                | "description"
                | "enum"
                | "items"
                | "properties"
                | "required"
                | "type"
        ) {
            return Err(CapabilityResultValidationError::MalformedArtifact(format!(
                "{path} uses unsupported result-schema keyword {keyword}"
            )));
        }
    }

    let schema_types = schema_types(object, path)?;
    let schema_type = schema_types
        .iter()
        .find(|value| value.as_str() != "null")
        .or_else(|| schema_types.first())
        .expect("a result schema with types is nonempty");

    // A KEYWORD THAT DOES NOT APPLY TO THE DECLARED TYPE IS A SILENT NO-OP, and
    // silence is the whole problem: enforcement reads only the keywords it knows
    // for the type in hand, so a misspelled `requried` or a `pattern` on a string
    // constrains nothing while reading, to its author, as a constraint. These
    // schemas are built by `json!` in this file rather than loaded from a pinned
    // artifact, so nothing else would catch the typo.
    //
    // Nullable objects still require a closed object schema. Inspect the
    // non-null type so the ordering of the type list cannot bypass that check.
    //
    // The computer plane has had this check since it was written; this side
    // did not, which is the mirror of the array-items hole that side had until
    // v12. Two validators for one rule diverge in BOTH directions.
    for keyword in object.keys() {
        let applicable = match schema_type.as_str() {
            "object" => matches!(
                keyword.as_str(),
                "additionalProperties"
                    | "description"
                    | "enum"
                    | "properties"
                    | "required"
                    | "type"
            ),
            "array" => matches!(keyword.as_str(), "description" | "enum" | "items" | "type"),
            _ => matches!(keyword.as_str(), "description" | "enum" | "type"),
        };
        if !applicable {
            return Err(CapabilityResultValidationError::MalformedArtifact(format!(
                "{path}.{keyword} does not apply to result type {schema_type}"
            )));
        }
    }
    if object
        .get("description")
        .is_some_and(|description| !description.is_string())
    {
        return Err(CapabilityResultValidationError::MalformedArtifact(format!(
            "{path}.description is not a string"
        )));
    }
    if let Some(choices) = object.get("enum") {
        let choices = choices.as_array().ok_or_else(|| {
            CapabilityResultValidationError::MalformedArtifact(format!(
                "{path}.enum is not an array"
            ))
        })?;
        if choices.is_empty()
            || choices.iter().any(|choice| {
                !schema_types
                    .iter()
                    .any(|schema_type| value_has_type(choice, schema_type))
            })
        {
            return Err(CapabilityResultValidationError::MalformedArtifact(format!(
                "{path}.enum is empty or disagrees with its type"
            )));
        }
    }

    match schema_type.as_str() {
        "object" => {
            let properties = object
                .get("properties")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    CapabilityResultValidationError::MalformedArtifact(format!(
                        "{path}.properties is not an object"
                    ))
                })?;
            if object.get("additionalProperties") != Some(&Value::Bool(false)) {
                return Err(CapabilityResultValidationError::MalformedArtifact(format!(
                    "{path} is not closed"
                )));
            }
            let required = object
                .get("required")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    CapabilityResultValidationError::MalformedArtifact(format!(
                        "{path}.required is not an array"
                    ))
                })?;
            for required_name in required {
                let required_name = required_name.as_str().ok_or_else(|| {
                    CapabilityResultValidationError::MalformedArtifact(format!(
                        "{path}.required contains a non-string"
                    ))
                })?;
                if !properties.contains_key(required_name) {
                    return Err(CapabilityResultValidationError::MalformedArtifact(format!(
                        "{path}.required names undeclared property {required_name}"
                    )));
                }
            }
            for (name, property_schema) in properties {
                validate_runtime_result_schema(property_schema, &format!("{path}.{name}"))?;
            }
        }
        "array" => {
            let items = object.get("items").ok_or_else(|| {
                CapabilityResultValidationError::MalformedArtifact(format!(
                    "{path}.items is missing"
                ))
            })?;
            validate_runtime_result_schema(items, &format!("{path}[]"))?;
        }
        _ => {
            if object.keys().any(|keyword| {
                matches!(
                    keyword.as_str(),
                    "additionalProperties" | "items" | "properties" | "required"
                )
            }) {
                return Err(CapabilityResultValidationError::MalformedArtifact(format!(
                    "{path} uses an object or array keyword for a scalar result type"
                )));
            }
        }
    }
    Ok(())
}

fn parse_browser_result_schema_table(
) -> Result<BTreeMap<String, Value>, CapabilityResultValidationError> {
    let mut table = BTreeMap::new();
    for definition in browser_tool_definitions() {
        validate_runtime_result_schema(
            &definition.result_schema,
            &format!("{}.result_schema", definition.name),
        )?;
        if table
            .insert(definition.name.to_string(), definition.result_schema)
            .is_some()
        {
            return Err(CapabilityResultValidationError::MalformedArtifact(format!(
                "duplicate result schema for {}",
                definition.name
            )));
        }
    }
    Ok(table)
}

fn browser_result_schema_table(
) -> Result<&'static BTreeMap<String, Value>, CapabilityResultValidationError> {
    static TABLE: OnceLock<Result<BTreeMap<String, Value>, CapabilityResultValidationError>> =
        OnceLock::new();
    match TABLE.get_or_init(parse_browser_result_schema_table) {
        Ok(table) => Ok(table),
        Err(error) => Err(error.clone()),
    }
}

fn collect_result_violations(
    schema: &Value,
    result: &Value,
    path: &str,
    violations: &mut Vec<CapabilityResultViolation>,
) {
    let object = schema
        .as_object()
        .expect("cached result schemas were validated while loading");
    if let Some(alternatives) = object.get("anyOf").and_then(Value::as_array) {
        let mut closest: Option<Vec<CapabilityResultViolation>> = None;
        for alternative in alternatives {
            let mut errors = Vec::new();
            collect_result_violations(alternative, result, path, &mut errors);
            if errors.is_empty() {
                return;
            }
            if closest
                .as_ref()
                .is_none_or(|prior| errors.len() < prior.len())
            {
                closest = Some(errors);
            }
        }
        violations.extend(closest.expect("validated alternatives are nonempty"));
        return;
    }
    let schema_types = schema_types(object, path)
        .expect("cached result schema types were validated while loading");
    if !schema_types
        .iter()
        .any(|schema_type| value_has_type(result, schema_type))
    {
        violations.push(CapabilityResultViolation::ExpectedType {
            path: path.to_string(),
            expected: schema_types.join("|"),
        });
        return;
    }
    if object
        .get("enum")
        .and_then(Value::as_array)
        .is_some_and(|choices| !choices.contains(result))
    {
        violations.push(CapabilityResultViolation::EnumMismatch {
            path: path.to_string(),
        });
    }

    if result.is_null() {
        return;
    }
    match schema_types
        .iter()
        .find(|value| value.as_str() != "null")
        .map(String::as_str)
    {
        Some("object") => {
            let result = result
                .as_object()
                .expect("the result type was checked above");
            let properties = object["properties"]
                .as_object()
                .expect("cached object schemas have properties");
            for required_name in object["required"]
                .as_array()
                .expect("cached object schemas have required lists")
            {
                let required_name = required_name
                    .as_str()
                    .expect("cached required names are strings");
                if !result.contains_key(required_name) {
                    violations.push(CapabilityResultViolation::MissingRequiredProperty {
                        path: path.to_string(),
                        property: required_name.to_string(),
                    });
                }
            }
            for (name, value) in result {
                let Some(property_schema) = properties.get(name) else {
                    violations.push(CapabilityResultViolation::UndeclaredProperty {
                        path: format!("{path}.{name}"),
                    });
                    continue;
                };
                collect_result_violations(
                    property_schema,
                    value,
                    &format!("{path}.{name}"),
                    violations,
                );
            }
        }
        Some("array") => {
            let items = object["items"]
                .as_object()
                .expect("cached arrays have item schemas");
            for (index, value) in result
                .as_array()
                .expect("the result type was checked above")
                .iter()
                .enumerate()
            {
                collect_result_violations(
                    &Value::Object(items.clone()),
                    value,
                    &format!("{path}[{index}]"),
                    violations,
                );
            }
        }
        _ => {}
    }
}

/// Check a served browser reply against the result schema declared beside its request schema.
pub fn validate_browser_result(
    capability_id: &str,
    result: &Value,
) -> Result<(), CapabilityResultValidationError> {
    let table = browser_result_schema_table()?;
    let schema = table.get(capability_id).ok_or_else(|| {
        CapabilityResultValidationError::UnknownCapability(capability_id.to_string())
    })?;
    if result.get("browser") == Some(&json!("user")) {
        return validate_user_browser_result(capability_id, result);
    }
    let mut violations = Vec::new();
    collect_result_violations(schema, result, "$", &mut violations);
    violations.sort();
    if violations.is_empty() {
        Ok(())
    } else {
        Err(CapabilityResultValidationError::ReplyViolations {
            capability_id: capability_id.to_string(),
            violations,
        })
    }
}

/// The extension target has tab-scoped results, not owned-process sessions.
/// Keep its closed vocabulary separate so existing own replies remain fixed.
pub(crate) fn validate_user_browser_result(
    action: &str,
    result: &Value,
) -> Result<(), CapabilityResultValidationError> {
    let mut schema = if matches!(action, "revoke_access" | crate::management::REVOKE_ACCESS) {
        let mut schema = revoke_access_result_schema();
        schema["properties"]["browser"] = enum_schema(&["user"]);
        schema
    } else {
        closed_object(
            json!({
                "browser":enum_schema(&["user"]),
                "outcome":enum_schema(&["ok","refused","closed","invalid_request","cancelled","outcome_unknown","authorization_denied","consent_pending"]),
                "ask_id":string_schema(),
            "reason":string_schema(), "remedy":string_schema(),
            "settled":boolean_schema(), "settlement_reason":string_schema(),
                "input_dispatched":{"anyOf":[boolean_schema(),{"type":"null"}]},
                "tab":string_schema(), "connected":boolean_schema(), "origin":string_schema(),
                "connection_epoch":integer_schema(), "interaction_epoch":integer_schema(),
                "tabs":{"type":"array","items":closed_object(json!({"tab":string_schema(),"claim":enum_schema(&["claimed_by_this_route","unclaimed_handed"]),"interaction_epoch":integer_schema()}), &["tab","claim","interaction_epoch"])},
                "snapshot_id":string_schema(), "state_text":string_schema(),
                "truncated":boolean_schema(), "refs_truncated":boolean_schema(),
                "omitted_frames":integer_schema(), "frame_note":string_schema(),
                "image":closed_object(json!({"mime":string_schema(),"data_b64":string_schema(),"width_px":integer_schema(),"height_px":integer_schema()}), &["mime","data_b64","width_px","height_px"]),
                "image_width_px":integer_schema(), "image_height_px":integer_schema(),
                "popup_activated_briefly":boolean_schema(),
                "detail":{"anyOf":[invalid_request_detail_result_schema(), closed_object(json!({"decision":string_schema()}), &["decision"]),
                    // Why no consent card could be raised, on `consent_unavailable`.
                    closed_object(json!({"reason":string_schema()}), &["reason"]),
                    // A cdp_error refusal names the rejected plan command and
                    // Chrome's fixed error code and message, never page text.
                    closed_object(json!({"method":string_schema(),"code":integer_schema(),"message":string_schema()}), &["method","code","message"]),
                    // An extension_outdated or extension_newer refusal names
                    // the extension's contract revision (null when it sent
                    // none) and the one this build requires.
                    closed_object(json!({"extension_revision":{"anyOf":[integer_schema(),{"type":"null"}]},"required_revision":integer_schema()}), &["extension_revision","required_revision"]),
                    // A protocol_error refusal names the decoding step and,
                    // when known, the reply field and what was wrong with it.
                    closed_object(json!({"step":string_schema(),"field":string_schema(),"problem":string_schema()}), &["step"])]}
            }),
            &["browser", "outcome"],
        )
    };
    let embedded = schema.clone();
    schema["properties"]["read_page"] = embedded;
    let mut violations = Vec::new();
    collect_result_violations(&schema, result, "$", &mut violations);
    violations.sort();
    if violations.is_empty() {
        Ok(())
    } else {
        Err(CapabilityResultValidationError::ReplyViolations {
            capability_id: format!("browser:user:{action}"),
            violations,
        })
    }
}

fn parse_severity(object: &Map<String, Value>) -> Result<Severity, BrowserError> {
    let value = object
        .get("severity")
        .ok_or_else(|| BrowserError::InvalidRequest {
            field: "severity".into(),
            reason_code: "missing_field",
        })?;
    let value = value
        .as_object()
        .ok_or_else(|| BrowserError::InvalidRequest {
            field: "severity".into(),
            reason_code: "wrong_type",
        })?;
    if let Some(field) = value
        .keys()
        .filter(|field| !matches!(field.as_str(), "tier" | "credential" | "financial"))
        .min()
    {
        return Err(BrowserError::InvalidRequest {
            field: format!("severity.{field}"),
            reason_code: "unknown_field",
        });
    }
    let tier = match value.get("tier") {
        None => {
            return Err(BrowserError::InvalidRequest {
                field: "severity.tier".into(),
                reason_code: "missing_field",
            })
        }
        Some(Value::Number(number)) => {
            number
                .as_u64()
                .ok_or_else(|| BrowserError::InvalidRequest {
                    field: "severity.tier".into(),
                    reason_code: "out_of_range",
                })?
        }
        Some(_) => {
            return Err(BrowserError::InvalidRequest {
                field: "severity.tier".into(),
                reason_code: "wrong_type",
            })
        }
    };
    if !(1..=5).contains(&tier) {
        return Err(BrowserError::InvalidRequest {
            field: "severity.tier".into(),
            reason_code: "out_of_range",
        });
    }
    let credential = value
        .get("credential")
        .and_then(Value::as_bool)
        .ok_or_else(|| BrowserError::InvalidRequest {
            field: "severity.credential".into(),
            reason_code: "wrong_type",
        })?;
    let financial = value
        .get("financial")
        .and_then(Value::as_bool)
        .ok_or_else(|| BrowserError::InvalidRequest {
            field: "severity.financial".into(),
            reason_code: "wrong_type",
        })?;
    Ok(Severity::new(tier as u8, credential, financial))
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    min: usize,
    max: usize,
) -> Result<&'a str, BrowserError> {
    let value = object
        .get(field)
        .ok_or_else(|| BrowserError::InvalidRequest {
            field: field.into(),
            reason_code: "missing_field",
        })?;
    let value = value.as_str().ok_or_else(|| BrowserError::InvalidRequest {
        field: field.into(),
        reason_code: "wrong_type",
    })?;
    if value.len() < min || value.len() > max {
        return Err(BrowserError::InvalidRequest {
            field: field.into(),
            reason_code: "out_of_range",
        });
    }
    Ok(value)
}
fn bounded_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    min: usize,
    max: usize,
) -> Result<&'a str, BrowserError> {
    required_string(object, field, min, max)
}
fn optional_bool(object: &Map<String, Value>, field: &str) -> Result<Option<bool>, BrowserError> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| BrowserError::InvalidRequest {
            field: field.into(),
            reason_code: "wrong_type",
        })
}
fn optional_integer(
    object: &Map<String, Value>,
    field: &str,
    min: u64,
    max: u64,
) -> Result<Option<u64>, BrowserError> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    let value = value.as_u64().ok_or_else(|| BrowserError::InvalidRequest {
        field: field.into(),
        reason_code: "wrong_type",
    })?;
    if value < min || value > max {
        return Err(BrowserError::InvalidRequest {
            field: field.into(),
            reason_code: "out_of_range",
        });
    }
    Ok(Some(value))
}
fn partial_error_result(error: &BrowserError) -> Value {
    let mut result = Map::new();
    result.insert("outcome".into(), Value::String(error.outcome().into()));
    result.insert("remedy".into(), Value::String(error.remedy().into()));
    if let Some(detail) = error.detail() {
        result.insert("detail".into(), detail);
    }
    Value::Object(result)
}

fn required_signed_integer(object: &Map<String, Value>, field: &str) -> Result<i128, BrowserError> {
    let value = object
        .get(field)
        .ok_or_else(|| BrowserError::InvalidRequest {
            field: field.into(),
            reason_code: "missing_field",
        })?;
    let value = value.as_i64().ok_or_else(|| BrowserError::InvalidRequest {
        field: field.into(),
        reason_code: "wrong_type",
    })?;
    if !(-9_007_199_254_740_991..=9_007_199_254_740_991).contains(&value) {
        return Err(BrowserError::InvalidRequest {
            field: field.into(),
            reason_code: "out_of_range",
        });
    }
    Ok(value as i128)
}
fn refusal_ring_config() -> RefusalRingConfig {
    RefusalRingConfig {
        records_per_caller: DEFAULT_REFUSAL_RECORDS_PER_CALLER,
    }
}

fn map_authorization_error(error: crate::authorization::AuthorizationError) -> BrowserError {
    match error {
        crate::authorization::AuthorizationError::NoGrant => {
            BrowserError::AuthorizationDenied { reason: "no_grant" }
        }
        crate::authorization::AuthorizationError::NoGrantForAction {
            attempted_origin,
            required,
        } => BrowserError::AuthorizationNoGrantForAction {
            attempted_origin,
            required,
        },
        crate::authorization::AuthorizationError::GrantSeverityInsufficient {
            attempted_origin,
            required,
            granted_ceilings,
        } => BrowserError::AuthorizationSeverityInsufficient {
            attempted_origin,
            required,
            granted_ceilings,
        },
        crate::authorization::AuthorizationError::OriginScope {
            attempted_origin,
            granted_origins,
            required,
            required_hazards,
        } => BrowserError::AuthorizationOriginScope {
            attempted_origin,
            granted_origins,
            required,
            required_hazards,
        },
        crate::authorization::AuthorizationError::HazardNotDisclosed {
            missing,
            attempted_origin,
            required,
            required_hazards,
        } => BrowserError::HazardNotDisclosed {
            missing,
            classification_unavailable: None,
            attempted_origin,
            required,
            required_hazards,
        },
        crate::authorization::AuthorizationError::SeverityBelowFloor { required } => {
            BrowserError::SeverityBelowFloor {
                required,
                classification_unavailable: None,
            }
        }
        crate::authorization::AuthorizationError::SeverityUnclassifiable => {
            BrowserError::InvalidRequest {
                field: "severity".into(),
                reason_code: "severity_unclassifiable",
            }
        }
        _ => BrowserError::Internal {
            reason_code: JournalReasonCode::InternalFailure,
        },
    }
}
/// Whether the page still shows the document a snapshot or screenshot was
/// taken from, checked immediately before an action dispatches input.
///
/// A ref or a pixel names something in one document. If the page has since
/// committed another document -- by its own script, a late redirect, a reload
/// -- the input would land in a page nobody read, under the grant for the
/// page that was read. The comparison is the document loader, not the history
/// entry: a fragment change or `history.pushState` adds a history entry but
/// keeps the document and every element in it, so it must stay actionable.
/// Anything unknown refuses.
fn check_snapshot_document(
    recorded: Option<&CommittedDocument>,
    live: Result<CommittedDocument, crate::browser_session::NavigationDriveError>,
) -> Result<(), BrowserError> {
    let live = live.map_err(map_navigation_drive_error)?;
    let Some(recorded) = recorded else {
        return Err(BrowserError::StaleSnapshot {
            reason_code: "snapshot_document_unknown",
        });
    };
    if recorded.loader_id == live.loader_id {
        return Ok(());
    }
    Err(BrowserError::PageChangedSinceSnapshot {
        snapshot_origin: origin_from_url(&recorded.url),
        live_origin: origin_from_url(&live.url),
    })
}

fn origin_from_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return "null".to_string();
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, value)| value);
    format!(
        "{}://{}",
        scheme.to_ascii_lowercase(),
        authority.to_ascii_lowercase()
    )
}
/// Durable refusal details describe the decision, not the page under the mouse.
/// Accessible names can contain private page text and must not enter the journal.
fn journal_refusal_detail(error: &BrowserError) -> Value {
    let mut detail = error.detail().unwrap_or_else(|| json!({}));
    if let Some(object) = detail.as_object_mut() {
        object.remove("hit_name");
        object.insert("outcome".into(), json!(error.outcome()));
    }
    detail
}

fn journal_outcome(error: &BrowserError) -> Outcome {
    match error {
        BrowserError::InvalidRequest { .. } | BrowserError::SeverityBelowFloor { .. } => {
            Outcome::InvalidRequest
        }
        BrowserError::AuthorizationDenied { .. }
        | BrowserError::AuthorizationOriginScope { .. }
        | BrowserError::AuthorizationNoGrantForAction { .. }
        | BrowserError::AuthorizationSeverityInsufficient { .. }
        | BrowserError::HazardNotDisclosed { .. }
        | BrowserError::PageNavigatedDuringRead { .. } => Outcome::Denied,
        BrowserError::StaleSnapshot { .. }
        | BrowserError::PageChangedSinceSnapshot { .. }
        | BrowserError::RefNotFound { .. }
        | BrowserError::RefAmbiguous { .. } => Outcome::StaleSnapshot,
        BrowserError::ClassificationUnavailable(_)
        | BrowserError::Intercepted(_)
        | BrowserError::ElementIntercepted
        | BrowserError::OutsideViewportAfterScroll { .. }
        | BrowserError::PointOutsideViewport { .. }
        | BrowserError::InvalidCoordinates { .. }
        | BrowserError::ImageTooLarge { .. } => Outcome::InvalidRequest,
        BrowserError::NoSession
        | BrowserError::BrowserLaunchPending
        | BrowserError::HumanInControl { .. }
        | BrowserError::Internal { .. }
        | BrowserError::CdpStepFailure { .. }
        | BrowserError::SessionStateUnavailable
        | BrowserError::BrowserCrashed
        | BrowserError::NotSettled { .. }
        | BrowserError::NavigationFailed { .. }
        | BrowserError::NavigationPolicyRejected { .. } => Outcome::InternalError,
        BrowserError::CommandTimeout { .. }
        | BrowserError::TypeNotReady { .. }
        | BrowserError::NavigateNotReady { .. } => Outcome::InvalidRequest,
    }
}
/// One journal capability per browser capability, with no collapsing.
///
/// The three observations used to fold onto Navigate, so a read of a page in a
/// durable profile persisted as a page load. That is worse than not recording
/// it: an absent entry is honest about being absent, and a wrong one is read as
/// authoritative -- permanently, since the journal directory is enrolled for
/// fleet backup.
fn journal_capability(capability: BrowserCapability) -> JournalCapability {
    match capability {
        BrowserCapability::Navigate => JournalCapability::Navigate,
        BrowserCapability::Click => JournalCapability::Click,
        BrowserCapability::Type => JournalCapability::Type,
        BrowserCapability::ClickPoint => JournalCapability::ClickPoint,
        BrowserCapability::Snapshot => JournalCapability::Snapshot,
        BrowserCapability::Screenshot => JournalCapability::Screenshot,
        BrowserCapability::Scroll => JournalCapability::Scroll,
        BrowserCapability::WaitFor => JournalCapability::WaitFor,
    }
}
fn map_journal_error(error: JournalError) -> BrowserError {
    BrowserError::Internal {
        reason_code: error.reason_code,
    }
}

fn map_navigation_drive_error(error: crate::browser_session::NavigationDriveError) -> BrowserError {
    match error {
        crate::browser_session::NavigationDriveError::NavigateNotReady {
            reason_code,
            navigation_sent,
        } => BrowserError::NavigateNotReady {
            reason_code,
            navigation_sent,
        },
        crate::browser_session::NavigationDriveError::FrameChanged {
            authorized_origin,
            live_origin,
        } => BrowserError::PageNavigatedDuringRead {
            authorized_origin,
            live_origin,
        },
        crate::browser_session::NavigationDriveError::NavigationFailed { error_text } => {
            BrowserError::NavigationFailed { error_text }
        }
        crate::browser_session::NavigationDriveError::Unavailable
        | crate::browser_session::NavigationDriveError::ConnectorFailure => {
            BrowserError::Internal {
                reason_code: JournalReasonCode::ConnectorFailure,
            }
        }
        crate::browser_session::NavigationDriveError::CommandDeadline {
            method,
            command_sent,
        } => BrowserError::CommandTimeout {
            step: method,
            command_sent,
        },
        crate::browser_session::NavigationDriveError::CdpStepFailure { method }
        | crate::browser_session::NavigationDriveError::NodeUnavailable { method } => {
            BrowserError::CdpStepFailure { step: method }
        }
        crate::browser_session::NavigationDriveError::CdpFailure
        | crate::browser_session::NavigationDriveError::CommandFailed { .. } => {
            BrowserError::Internal {
                reason_code: JournalReasonCode::CdpFailure,
            }
        }
        crate::browser_session::NavigationDriveError::StateUnavailable => {
            BrowserError::SessionStateUnavailable
        }
    }
}

fn map_snapshot_error(error: SnapshotError) -> BrowserError {
    match error {
        SnapshotError::WrongKind => BrowserError::StaleSnapshot {
            reason_code: "snapshot_kind_mismatch",
        },
        SnapshotError::EpochMismatch => BrowserError::StaleSnapshot {
            reason_code: "document_epoch_changed",
        },
        SnapshotError::Evicted | SnapshotError::NotFound => BrowserError::StaleSnapshot {
            reason_code: "snapshot_evicted",
        },
        SnapshotError::Ambiguous { candidate_count } => {
            BrowserError::RefAmbiguous { candidate_count }
        }
        SnapshotError::RetentionFull => BrowserError::Internal {
            reason_code: JournalReasonCode::ResultSerializationLimit,
        },
        SnapshotError::EpochOverflow
        | SnapshotError::BoundExceeded
        | SnapshotError::InvalidId
        | SnapshotError::InvalidRef
        | SnapshotError::IdentityOutOfBounds
        | SnapshotError::Serialization
        | SnapshotError::Teardown => BrowserError::Internal {
            reason_code: JournalReasonCode::InternalFailure,
        },
    }
}
fn map_coordinate_error(error: CoordinateError) -> BrowserError {
    match error {
        CoordinateError::InvalidCoordinates { reason } => {
            BrowserError::InvalidCoordinates { reason }
        }
        CoordinateError::ImageTooLarge {
            encoded_bytes,
            bound_bytes,
        } => BrowserError::ImageTooLarge {
            bytes: encoded_bytes,
            bound_bytes,
        },
        CoordinateError::CdpFailure => BrowserError::Internal {
            reason_code: JournalReasonCode::CdpFailure,
        },
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn stable_refs_reopening_a_context_does_not_recycle_names() {
        let plane = BrowserPlane::new();
        let identity = identity();
        let record = crate::snapshot_store::RefRecord {
            frame_document: None,
            captured: crate::snapshot_store::SnapshotRef::new("e1", "button", "Access", 0).unwrap(),
            frame_path: vec!["frame".into()],
            backend_identity: Some(
                crate::snapshot_store::BackendNodeIdentity::new("target", "frame", 42).unwrap(),
            ),
            raw_role: None,
            raw_name: None,
            classification: Err(ClassificationUnavailable::NotCaptured),
        };
        let records = [AxRecord {
            depth: 0,
            role: "button".into(),
            name: "Access".into(),
            value: None,
            reference: Some("e1".into()),
        }];
        let mut names = Vec::new();
        for loader in ["first", "second"] {
            plane.open_context(identity.clone()).await.unwrap();
            let snapshot = plane
                .retain_text_snapshot(
                    &identity,
                    SnapshotKind::Ax,
                    &records,
                    None,
                    vec![record.clone()],
                    4096,
                    Some(CommittedDocument::new("https://example.com", 1, loader)),
                )
                .await
                .unwrap();
            let row: Value =
                serde_json::from_str(snapshot["state_text"].as_str().unwrap().trim()).unwrap();
            names.push(row["ref"].as_str().unwrap().to_string());
        }
        assert_eq!(names, ["e1", "e2"]);
        let state = plane.state.lock().await;
        let context = state.contexts.get(&identity.conversation_key).unwrap();
        assert!(context.refs.shown("e1").is_none());
    }

    /// A printed ref survives insertions but cannot fall back to a fresh node
    /// occupying its old capture position after removal.
    #[test]
    fn stable_refs_zoom_rejects_removed_identity() {
        let record = |reference: &str, backend: u64| crate::snapshot_store::RefRecord {
            frame_document: None,
            captured: crate::snapshot_store::SnapshotRef::new(reference, "article", "Post", 0)
                .unwrap(),
            frame_path: vec!["frame".into()],
            backend_identity: Some(
                crate::snapshot_store::BackendNodeIdentity::new("target", "frame", backend)
                    .unwrap(),
            ),
            raw_role: None,
            raw_name: None,
            classification: Err(ClassificationUnavailable::NotCaptured),
        };
        let ax = |reference: &str| AxRecord {
            depth: 0,
            role: "article".into(),
            name: "Post".into(),
            value: None,
            reference: Some(reference.into()),
        };
        let mut context = ContextState::new(identity());
        let doc = CommittedDocument::new("https://example.com/", 1, "loader");
        let mut initial = vec![record("e5", 50)];
        context.refs.assign(
            &mut [ax("e5")],
            &mut initial,
            &mut HashMap::new(),
            0,
            Some(&doc),
        );
        context.refs.remember(&initial, "previous", 0, Some(&doc));
        let requested = initial[0].captured.reference.clone();
        let mut fresh = vec![record("e5", 70), record("e6", 60), record("e7", 50)];
        context.refs.assign(
            &mut [ax("e5"), ax("e6"), ax("e7")],
            &mut fresh,
            &mut HashMap::new(),
            0,
            Some(&doc),
        );
        assert_eq!(fresh[2].captured.reference, requested);
        assert_ne!(fresh[0].captured.reference, requested);
        let mut recached = fresh.clone();
        recached[2].captured.reference = "e99999".into();
        assert_eq!(
            zoom_target(&context, &requested, &recached, Some(&doc)).unwrap(),
            Some("e99999".into())
        );
        assert_eq!(
            zoom_target(&context, &requested, &fresh, Some(&doc)).unwrap(),
            Some(requested.clone())
        );
        assert_eq!(
            zoom_target(&context, &requested, &fresh[..2], Some(&doc)).unwrap(),
            None
        );
        // Even a corrupted fresh capture must not resolve by number alone.
        fresh[0].captured.reference = requested.clone();
        assert_eq!(
            zoom_target(&context, &requested, &fresh[..1], Some(&doc)).unwrap(),
            None
        );
        assert_eq!(
            zoom_target(&context, "e999", &fresh, Some(&doc)).unwrap(),
            None
        );
        let changed = CommittedDocument::new("https://example.com/", 2, "new-loader");
        assert!(matches!(
            zoom_target(&context, &requested, &fresh, Some(&changed)),
            Err(BrowserError::StaleSnapshot {
                reason_code: "document_or_target_changed"
            })
        ));
        let mut identityless = initial.clone();
        identityless[0].backend_identity = None;
        context
            .refs
            .remember(&identityless, "previous", 0, Some(&doc));
        assert!(matches!(
            zoom_target(&context, &requested, &fresh, Some(&doc)),
            Err(BrowserError::StaleSnapshot {
                reason_code: "ref_from_older_snapshot"
            })
        ));
    }

    /// `max_bytes` bounds the page text in every mode, the reply's copy of a
    /// huge source URL is cut, and the reply still matches its declared
    /// schema on a plane that withholds any reply that does not.
    #[tokio::test]
    async fn snapshot_state_text_cap_and_long_source_hold_in_every_mode() {
        let route = identity();
        let plane =
            BrowserPlane::new().with_result_schema_enforcement(ResultSchemaEnforcement::Withhold);
        plane.open_context(route.clone()).await.unwrap();
        let records: Vec<_> = (0..1000)
            .map(|i| AxRecord {
                depth: 0,
                role: "link".into(),
                name: format!("quoted \"\\\" café {i} ").repeat(20),
                value: None,
                reference: Some(format!("e{}", i + 1)),
            })
            .collect();
        let refs: Vec<_> = records
            .iter()
            .map(|r| crate::snapshot_store::RefRecord {
                frame_document: None,
                captured: crate::snapshot_store::SnapshotRef::new(
                    r.reference.clone().unwrap(),
                    &r.role,
                    &r.name,
                    0,
                )
                .unwrap(),
                frame_path: vec![],
                backend_identity: None,
                raw_role: None,
                raw_name: None,
                classification: Err(crate::classification::ClassificationUnavailable::NotCaptured),
            })
            .collect();
        let (text, _) = snapshot_store::encode_ax_jsonl(&records, usize::MAX).unwrap();
        for mode in [
            SnapshotKind::Actionable,
            SnapshotKind::Ax,
            SnapshotKind::DomFull,
        ] {
            for budget in [1, 512, 1024, 20000] {
                let reply = plane
                    .retain_text_snapshot(
                        &route,
                        mode,
                        &records,
                        Some(&text),
                        refs.clone(),
                        budget,
                        Some(CommittedDocument::new(
                            format!("https://example.com/{}", "long".repeat(10000)),
                            1,
                            "loader",
                        )),
                    )
                    .await
                    .unwrap();
                let reply = plane.result(&route, Ok(reply)).await;
                let state_text = reply[state_text::STATE_TEXT_FIELD].as_str().unwrap();
                assert!(state_text.len() <= budget, "{mode:?}, budget {budget}");
                assert!(
                    reply["source_origin"].as_str().unwrap().len()
                        <= snapshot_store::MAX_SOURCE_ORIGIN_BYTES
                );
                assert_eq!(reply["omitted"]["source_origin"], true);
                if budget == 1 || mode != SnapshotKind::Actionable {
                    assert_eq!(reply["truncated"], true, "{mode:?}, budget {budget}");
                    assert!(reply["omitted"]["state_text_bytes"].as_u64().unwrap() > 0);
                }
                assert_eq!(reply["mode"], mode.as_str());
                assert!(reply.get("content").is_none() && reply.get("refs").is_none());
                plane.finish_reply(SNAPSHOT, reply).unwrap();
            }
        }
    }

    /// Each browser capability maps to its OWN journal capability.
    ///
    /// Asserting the mapping rather than the enum, which is the mistake I made
    /// first: a test over `Capability::as_str` checks that the names differ
    /// from each other and never calls the function that decides which name a
    /// dispatch gets. Restoring the old fold -- Snapshot onto Navigate -- left
    /// that test green, because the enum was still correct and the mapping was
    /// not what it examined.
    ///
    /// The pairs are literals so a mapping change cannot satisfy this by moving
    /// both sides at once, and the injectivity check is what actually catches a
    /// fold, since a fold produces a duplicate rather than a wrong name.
    #[test]
    fn every_browser_capability_journals_under_its_own_name() {
        use std::collections::BTreeSet;

        let pairs = [
            (BrowserCapability::Navigate, JournalCapability::Navigate),
            (BrowserCapability::Click, JournalCapability::Click),
            (BrowserCapability::ClickPoint, JournalCapability::ClickPoint),
            (BrowserCapability::Snapshot, JournalCapability::Snapshot),
            (BrowserCapability::Screenshot, JournalCapability::Screenshot),
            (BrowserCapability::Scroll, JournalCapability::Scroll),
            (BrowserCapability::WaitFor, JournalCapability::WaitFor),
        ];

        let mut journaled = BTreeSet::new();
        for (browser, expected) in pairs {
            let actual = journal_capability(browser);
            assert_eq!(
                actual, expected,
                "{browser:?} journals as {actual:?}, not as itself"
            );
            assert!(
                journaled.insert(actual.as_str()),
                "{browser:?} shares a journal name with another capability"
            );
        }
        assert_eq!(
            journaled.len(),
            7,
            "a browser capability was added without a journal name of its own"
        );
    }

    /// An observation records no action, and an actuation records one.
    ///
    /// Both directions, because asserting only the None side passes if every
    /// capability returns None, which would empty the record of every action
    /// this journal exists to hold.
    #[test]
    fn only_actuating_capabilities_record_an_action() {
        for capability in [
            JournalCapability::Snapshot,
            JournalCapability::Screenshot,
            JournalCapability::WaitFor,
        ] {
            assert!(
                journal_action(capability).is_none(),
                "{capability:?} is an observation and performs no action"
            );
        }
        for capability in [
            JournalCapability::Navigate,
            JournalCapability::Click,
            JournalCapability::ClickPoint,
            JournalCapability::Type,
            JournalCapability::Scroll,
        ] {
            assert!(
                journal_action(capability).is_some(),
                "{capability:?} actuates and must record what it did"
            );
        }
    }
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn click_and_navigate_share_loaded_but_unsettled_lifecycle() {
        let plane = BrowserPlane::new();
        let route = identity();
        plane.open_context(route.clone()).await.unwrap();
        let mut tracker = Tracker {
            url_final: Some("https://example.test/page".into()),
            ..Tracker::default()
        };
        tracker.load(Instant::now());
        let expected = json!({"events":["load"],"loaded":true,"settled":false});
        assert_eq!(navigate_reply(&tracker, true)["lifecycle"], expected);
        let reply = plane
            .click_reply(
                &route,
                crate::browser_session::BrowserClickOutcome::Clicked {
                    position: crate::browser_session::BrowserClickPosition {
                        x_css: 1.0,
                        y_css: 1.0,
                    },
                    navigation: crate::browser_session::ClickNavigation::MainFrame(Box::new(
                        tracker,
                    )),
                },
            )
            .await;
        assert_eq!(reply["outcome"], "ok");
        assert_eq!(reply["lifecycle"], expected);
        let reply = plane.result(&route, Ok(reply)).await;
        assert!(validate_browser_result(CLICK, &reply).is_ok());
    }

    fn identity() -> RouteIdentity {
        RouteIdentity::from_bind(
            &subc_protocol::BindIdentity::new("/tmp/project", "test", "conversation"),
            &Some(subc_protocol::Principal::Direct),
        )
    }

    fn severity() -> Value {
        json!({"tier":1,"credential":false,"financial":false})
    }

    /// A grant covering this module's test conversation and origin.
    ///
    /// The authorization gate always runs and an empty store covers nothing, so
    /// a test about anything downstream of it must arrive holding the authority
    /// a real caller would hold.
    fn test_grants() -> GrantStore {
        GrantStore::new([crate::authorization::ActionGrant::new(
            "browser-mod-test-grant",
            1,
            identity().conversation_key.clone(),
            crate::authorization::Severity {
                tier: 4,
                credential: false,
                financial: false,
            },
            ["https://example.test"],
        )])
    }

    #[tokio::test]
    async fn authorization_refusals_with_different_remedies_have_distinct_wire_outcomes() {
        let plane = BrowserPlane::new();
        let identity = identity();
        let denied = plane
            .result(
                &identity,
                Err(BrowserError::AuthorizationDenied { reason: "no_grant" }),
            )
            .await;
        let undisclosed = plane
            .result(
                &identity,
                Err(BrowserError::HazardNotDisclosed {
                    missing: HazardClass::CredentialFormSubmit,
                    classification_unavailable: None,
                    attempted_origin: "https://example.test".into(),
                    required: Severity::new(4, true, false),
                    required_hazards: [HazardClass::CredentialFormSubmit].into(),
                }),
            )
            .await;

        assert_eq!(denied["outcome"], "authorization_denied");
        assert_eq!(undisclosed["outcome"], "hazard_not_disclosed");
        assert_ne!(
            denied["outcome"], undisclosed["outcome"],
            "refusals requiring different grants must not collapse to one wire outcome"
        );
        assert_eq!(
            undisclosed["detail"]["missing_hazard"],
            "credential_form_submit"
        );
    }

    /// A grant gets its credential and financial flags only from disclosed
    /// hazards, so a grant request for a flagged severity must name those
    /// hazards or the grant it mints would still fall short. A tier no grant
    /// can reach gets no grant request at all.
    #[tokio::test]
    async fn a_grant_request_names_the_hazards_that_supply_the_required_flags() {
        let plane = BrowserPlane::new();
        let identity = identity();
        let flagged = plane
            .result(
                &identity,
                Err(BrowserError::AuthorizationNoGrantForAction {
                    attempted_origin: "https://example.test".into(),
                    required: crate::authorization::Severity::new(4, true, true),
                }),
            )
            .await;
        assert_eq!(
            flagged["detail"]["grant_request"],
            json!({
                "origins": ["https://example.test"],
                "severity_tier": 4,
                "hazards": ["credential_form_submit", "financial_form_submit"],
            }),
            "{flagged}"
        );
        let unreachable = plane
            .result(
                &identity,
                Err(BrowserError::AuthorizationNoGrantForAction {
                    attempted_origin: "https://example.test".into(),
                    required: crate::authorization::Severity::new(5, false, false),
                }),
            )
            .await;
        assert!(
            unreachable["detail"].get("grant_request").is_none(),
            "{unreachable}"
        );
        assert_eq!(unreachable["detail"]["required"]["tier"], 5);

        // The unverified-form hazard already supplies both flags, so the
        // request discloses it alone rather than two more hazard classes.
        let unverified = plane
            .result(
                &identity,
                Err(BrowserError::AuthorizationOriginScope {
                    attempted_origin: "https://example.test".into(),
                    granted_origins: vec!["https://other.test".into()],
                    required: Severity::new(4, true, true),
                    required_hazards: [HazardClass::UnverifiedFormContents].into(),
                }),
            )
            .await;
        assert_eq!(
            unverified["detail"]["grant_request"],
            json!({
                "origins": ["https://example.test"],
                "severity_tier": 4,
                "hazards": ["unverified_form_contents"],
            }),
            "{unverified}"
        );

        // A non-http(s) origin cannot be named by any grant, so no arguments
        // are offered and the remedy says to leave the page instead.
        let opaque = plane
            .result(
                &identity,
                Err(BrowserError::AuthorizationNoGrantForAction {
                    attempted_origin: "file://".into(),
                    required: Severity::new(1, false, false),
                }),
            )
            .await;
        assert!(opaque["detail"].get("grant_request").is_none(), "{opaque}");
        assert_eq!(
            opaque["remedy"],
            "no grant can name detail.attempted_origin; navigate to an http or https page, then retry",
            "{opaque}"
        );
    }

    /// A grant with no hazards is minted at compose however low a tier it is
    /// asked for, so a refusal for a tier-1 read names tier 2: the tier the
    /// grant will really carry, not one it can never be minted at.
    #[tokio::test]
    async fn a_grant_request_names_the_tier_the_grant_is_minted_at() {
        let plane = BrowserPlane::new();
        let refused = plane
            .result(
                &identity(),
                Err(BrowserError::AuthorizationNoGrantForAction {
                    attempted_origin: "https://example.test".into(),
                    required: Severity::new(crate::authorization::OBSERVE, false, false),
                }),
            )
            .await;
        assert_eq!(
            refused["detail"]["grant_request"]["severity_tier"],
            crate::management::NO_HAZARD_GRANT_TIER,
            "{refused}"
        );
        assert_eq!(refused["detail"]["required"]["tier"], 1, "{refused}");
    }

    #[tokio::test]
    async fn every_browser_error_serializes_its_exact_caller_remedy() {
        let cases = vec![
            (
                "invalid_request",
                BrowserError::InvalidRequest {
                    field: "url".to_string(),
                    reason_code: "wrong_type",
                },
                "invalid_request",
                "correct detail.field according to detail.reason_code, then resubmit the request",
            ),
            (
                "no_session",
                BrowserError::NoSession,
                "no_session",
                "call browser.launch, then retry the browser action",
            ),
            (
                "browser_launch_pending",
                BrowserError::BrowserLaunchPending,
                "browser_launch_pending",
                "poll browser.status until the session is ready, then retry the browser action",
            ),
            (
                "stale_snapshot",
                BrowserError::StaleSnapshot {
                    reason_code: "document_epoch_changed",
                },
                "stale_snapshot",
                "call browser.snapshot again and use only its new snapshot_id and refs",
            ),
            (
                "ref_not_found",
                BrowserError::RefNotFound {
                    reference: "e1".to_string(),
                },
                "ref_not_found",
                "choose a ref listed in the snapshot identified by snapshot_id",
            ),
            (
                "ref_ambiguous",
                BrowserError::RefAmbiguous { candidate_count: 2 },
                "ref_ambiguous",
                "take a fresh browser.snapshot and choose a ref that identifies exactly one current element",
            ),
            (
                "element_intercepted",
                BrowserError::ElementIntercepted,
                "element_intercepted",
                "take a fresh browser.snapshot and choose a ref that currently exposes a clickable position",
            ),
            (
                "coordinates_out_of_bounds",
                BrowserError::InvalidCoordinates {
                    reason: InvalidCoordinatesReason::PointOutOfBounds,
                },
                "invalid_coordinates",
                "address a pixel inside the declared image: 0 <= x < image_width_px and 0 <= y < image_height_px",
            ),
            (
                "coordinates_non_finite",
                BrowserError::InvalidCoordinates {
                    reason: InvalidCoordinatesReason::NonFiniteMetadata,
                },
                "invalid_coordinates",
                "take a fresh screenshot: this one's retained geometry cannot be mapped",
            ),
            (
                "coordinates_non_positive_dimensions",
                BrowserError::InvalidCoordinates {
                    reason: InvalidCoordinatesReason::NonPositiveDimensions,
                },
                "invalid_coordinates",
                "take a fresh screenshot: this one reports no area to address",
            ),
            (
                "coordinates_conversion_failure",
                BrowserError::InvalidCoordinates {
                    reason: InvalidCoordinatesReason::ConversionFailure,
                },
                "invalid_coordinates",
                "take a fresh screenshot: this one's retained geometry cannot be mapped",
            ),
            (
                "coordinates_image_size_mismatch",
                BrowserError::InvalidCoordinates {
                    reason: InvalidCoordinatesReason::ImageSizeMismatch,
                },
                "invalid_coordinates",
                "send coordinates in the space of the image this module declared, and pass its image_width_px and image_height_px. If a model was shown a resized copy, multiply its coordinates by declared/shown before sending them.",
            ),
            (
                "image_too_large",
                BrowserError::ImageTooLarge {
                    bytes: 20,
                    bound_bytes: 10,
                },
                "image_too_large",
                "use browser.snapshot for a text observation, or reduce the viewport before capturing another image",
            ),
            (
                "authorization_denied",
                BrowserError::AuthorizationDenied { reason: "no_grant" },
                "authorization_denied",
                "retry the browser action; if it is refused again, follow that refusal's remedy",
            ),
            (
                "origin_scope",
                BrowserError::AuthorizationOriginScope {
                    attempted_origin: "https://example.test".into(),
                    granted_origins: vec!["https://other.test".into()],
                    required: crate::authorization::Severity::new(1, false, false),
                    required_hazards: Default::default(),
                },
                "authorization_denied",
                "call browser.open_grant with the arguments in detail.grant_request, then retry",
            ),
            (
                "no_grant_for_action",
                BrowserError::AuthorizationNoGrantForAction {
                    attempted_origin: "https://example.test".into(),
                    required: crate::authorization::Severity::new(4, true, false),
                },
                "authorization_denied",
                "call browser.open_grant with the arguments in detail.grant_request, then retry",
            ),
            (
                "grant_severity_insufficient",
                BrowserError::AuthorizationSeverityInsufficient {
                    attempted_origin: "https://example.test".into(),
                    required: crate::authorization::Severity::new(4, false, true),
                    granted_ceilings: vec![crate::authorization::Severity::new(2, false, false)],
                },
                "authorization_denied",
                "call browser.open_grant with the arguments in detail.grant_request, then retry",
            ),
            (
                "grant_severity_insufficient_beyond_any_grant",
                BrowserError::AuthorizationSeverityInsufficient {
                    attempted_origin: "https://example.test".into(),
                    required: crate::authorization::Severity::new(5, false, false),
                    granted_ceilings: vec![crate::authorization::Severity::new(4, false, false)],
                },
                "authorization_denied",
                "no grant can be opened above tier 4; resubmit with a severity whose tier is at most 4",
            ),
            (
                "hazard_not_disclosed",
                BrowserError::HazardNotDisclosed {
                    missing: HazardClass::CredentialFormSubmit,
                    classification_unavailable: None,
                    attempted_origin: "https://example.test".into(),
                    required: crate::authorization::Severity::new(4, true, false),
                    required_hazards: [HazardClass::CredentialFormSubmit].into(),
                },
                "hazard_not_disclosed",
                "call browser.open_grant with the arguments in detail.grant_request, then retry",
            ),
            (
                "severity_below_floor",
                BrowserError::SeverityBelowFloor {
                    required: Severity::new(2, false, false),
                    classification_unavailable: None,
                },
                "invalid_request",
                "resubmit with detail.required as the severity; a grant must cover that severity for this target",
            ),
            (
                "navigation_policy_rejected",
                BrowserError::NavigationPolicyRejected {
                    reason_code: "scheme_not_allowed",
                },
                "navigation_policy_rejected",
                "navigate to an http or https URL allowed by browser policy",
            ),
            (
                "navigation_failed",
                BrowserError::NavigationFailed {
                    error_text: "net::ERR_NAME_NOT_RESOLVED".to_string(),
                },
                "navigation_failed",
                "inspect detail.error_text and choose a reachable destination or retry when that browser error is transient",
            ),
            (
                "page_navigated_during_read",
                BrowserError::PageNavigatedDuringRead {
                    authorized_origin: "https://granted.test".to_string(),
                    live_origin: "https://elsewhere.test".to_string(),
                },
                "page_navigated_during_read",
                "read the page again with browser.snapshot or browser.screenshot; if it stays on detail.live_origin, that read needs browser.open_grant for detail.live_origin first",
            ),
            (
                "page_changed_since_snapshot",
                BrowserError::PageChangedSinceSnapshot {
                    snapshot_origin: "https://granted.test".to_string(),
                    live_origin: "https://elsewhere.test".to_string(),
                },
                "stale_snapshot",
                "take a fresh browser.snapshot (or browser.screenshot for click_point) of the page as it is now and act on its snapshot_id; if detail.live_origin is not granted, that read needs browser.open_grant for it first",
            ),
            (
                "not_settled",
                BrowserError::NotSettled {
                    url_final: Some("https://example.test/".to_string()),
                    lifecycle: vec!["load".to_string()],
                    inflight_count: 1,
                    deadline_ms: 1_000,
                },
                "not_settled",
                "call browser.snapshot to re-observe the page before depending on its current state",
            ),
            (
                "browser_crashed",
                BrowserError::BrowserCrashed,
                "browser_crashed",
                "no caller remedy in v1: this module does not reconnect a crashed browser",
            ),
            (
                "internal_error",
                BrowserError::Internal {
                    reason_code: JournalReasonCode::InternalFailure,
                },
                "internal_error",
                "report this module failure with detail.reason_code and do not assume the action completed",
            ),
        ];
        let plane = BrowserPlane::new();
        let identity = identity();

        for (name, error, expected_outcome, expected_remedy) in cases {
            let reply = plane.result(&identity, Err(error)).await;
            assert_eq!(
                reply["outcome"], expected_outcome,
                "wrong outcome for {name}"
            );
            assert_eq!(reply["remedy"], expected_remedy, "wrong remedy for {name}");
            for capability in [
                BrowserCapability::Navigate,
                BrowserCapability::Snapshot,
                BrowserCapability::Click,
                BrowserCapability::Screenshot,
                BrowserCapability::ClickPoint,
                BrowserCapability::WaitFor,
            ] {
                assert!(
                    validate_browser_result(capability.name(), &reply).is_ok(),
                    "{name} is not declared by {}: {reply}",
                    capability.name()
                );
            }
        }
    }

    #[test]
    fn every_late_browser_refusal_names_its_exact_caller_remedy() {
        let cases = [
            (
                LateEvent::DownloadBlocked,
                "choose an in-page action that does not start a download",
            ),
            (
                LateEvent::JsDialogDismissed,
                "call browser.snapshot and continue from the page state after the dialog was dismissed",
            ),
            (
                LateEvent::NavigationPolicyRejected {
                    reason_code: "scheme_not_allowed".to_string(),
                },
                "navigate to an http or https URL allowed by browser policy",
            ),
            (
                LateEvent::AuthorizationDenied {
                    reason: "no_grant".to_string(),
                },
                "call browser.open_grant to mint a grant covering this action, then retry",
            ),
        ];

        for (event, expected_remedy) in cases {
            assert_eq!(
                event.remedy(),
                expected_remedy,
                "wrong remedy for {event:?}"
            );
        }
    }

    #[tokio::test]
    async fn every_late_browser_refusal_reaches_the_wait_result_schema() {
        for event in [
            LateEvent::DownloadBlocked,
            LateEvent::JsDialogDismissed,
            LateEvent::NavigationPolicyRejected {
                reason_code: "scheme_not_allowed".into(),
            },
            LateEvent::AuthorizationDenied {
                reason: "no_grant".into(),
            },
        ] {
            let plane = BrowserPlane::new();
            let identity = identity();
            plane.queue_event(&identity, event).await;
            let reply = plane
                .dispatch(
                    &identity,
                    BrowserCapability::WaitFor,
                    &json!({"deadline_ms": 0}),
                )
                .await;
            assert!(
                validate_browser_result(WAIT_FOR, &reply).is_ok(),
                "the wait handler emitted an undeclared late-event reply: {reply}"
            );
        }
    }

    #[tokio::test]
    async fn eight_tools_have_closed_descriptors_including_browser_type_and_scroll() {
        let tools = tool_definitions();
        assert_eq!(tools.len(), 8);
        assert!(tools.iter().any(|(name, _, _)| *name == SCROLL));
        assert!(tools.iter().any(|(name, _, _)| *name == TYPE));
        assert!(tools
            .iter()
            .all(|(_, _, schema)| schema["additionalProperties"] == false));
        let (_, description, schema) = tools
            .iter()
            .find(|(name, _, _)| *name == SCREENSHOT)
            .expect("screenshot remains dispatchable even though wire advertisement filters it");
        assert!(description.contains("PNG base64"));
        assert_eq!(schema["properties"]["max_bytes"]["type"], "integer");
        assert_eq!(schema["properties"]["max_bytes"]["minimum"], 1);
        assert_eq!(
            schema["properties"]["max_bytes"]["maximum"],
            MAX_ENCODED_PNG_BYTES
        );
    }

    /// Every capability the dispatcher accepts is also advertised.
    ///
    /// `handle_tool` admits any name [`BrowserCapability::parse`] recognizes,
    /// while the manifest is built from [`tool_definitions`], which is a list
    /// rather than a match -- so a capability added to the enum and wired
    /// through dispatch stays dispatchable without ever being declared, and a
    /// test that only counts the list still sees the expected number. The
    /// exhaustive match below exists so that adding a variant fails to compile
    /// here, forcing that decision to be made rather than defaulted.
    #[test]
    fn every_dispatchable_capability_is_advertised() {
        fn enumerate(capability: BrowserCapability) -> BrowserCapability {
            match capability {
                BrowserCapability::Navigate
                | BrowserCapability::Snapshot
                | BrowserCapability::Click
                | BrowserCapability::Type
                | BrowserCapability::Screenshot
                | BrowserCapability::Scroll
                | BrowserCapability::ClickPoint
                | BrowserCapability::WaitFor => capability,
            }
        }

        let dispatchable = [
            BrowserCapability::Navigate,
            BrowserCapability::Snapshot,
            BrowserCapability::Click,
            BrowserCapability::Type,
            BrowserCapability::Screenshot,
            BrowserCapability::Scroll,
            BrowserCapability::ClickPoint,
            BrowserCapability::WaitFor,
        ]
        .map(enumerate);

        let advertised: Vec<&str> = tool_definitions()
            .iter()
            .map(|(name, _, _)| *name)
            .collect();
        for capability in dispatchable {
            assert!(
                advertised.contains(&capability.name()),
                "{} is dispatchable but not advertised",
                capability.name()
            );
        }
        assert_eq!(
            advertised.len(),
            dispatchable.len(),
            "a tool is advertised that no capability dispatches"
        );
    }

    #[tokio::test]
    async fn navigation_without_a_session_never_opens_an_operation_bracket() {
        let plane = BrowserPlane::new().with_grants_installed(test_grants());
        let identity = identity();
        plane.open_context(identity.clone()).await.unwrap();
        let request = json!({"url":"https://example.test/","intent":"go","severity":severity(),"wait":"none"});
        let result = plane
            .dispatch(&identity, BrowserCapability::Navigate, &request)
            .await;

        assert_eq!(result["outcome"], "no_session");
        assert!(plane.operation_log().await.is_empty());
    }

    fn declared_navigate_reply() -> Value {
        json!({
            "outcome": "ok",
            "context": {
                "profile_uuid": null,
                "profile_name": "default",
                "session_kind_effective": "primary",
                "profile_disposition": "durable"
            }
        })
    }

    #[test]
    fn browser_result_schemas_are_closed_and_accept_optional_presence_or_absence() {
        let absent = declared_navigate_reply();
        assert!(validate_browser_result(NAVIGATE, &absent).is_ok());

        let mut present = declared_navigate_reply();
        present
            .as_object_mut()
            .expect("navigate reply is an object")
            .insert(
                "challenge".into(),
                json!({"vendor":"cloudflare","evidence":"cf-mitigated: challenge"}),
            );
        assert!(validate_browser_result(NAVIGATE, &present).is_ok());
    }

    #[test]
    fn every_browser_vocabulary_accepts_bounded_call_shapes() {
        let plane =
            BrowserPlane::new().with_result_schema_enforcement(ResultSchemaEnforcement::Withhold);
        for definition in browser_tool_definitions() {
            for step in [
                "admission",
                "queue",
                "consent",
                "preflight",
                "dispatch",
                "release",
            ] {
                let mut replies = vec![
                    json!({"outcome":"action_deadline_exceeded","detail":{"dispatched":false,"step":step}}),
                    json!({"outcome":"target_busy","detail":{"reason":"held_input_unconfirmed","dispatched":false,"step":step,"call":"browser.type","held_state":"unknown"},"remedy":"retry release before input"}),
                    json!({"outcome":"blocking_capacity_exhausted","detail":{"dispatched":false,"step":step,"call":"session operation"}}),
                ];
                for reason in [
                    "action_deadline_exceeded",
                    "cancelled",
                    "route_closed",
                    "module_draining",
                ] {
                    for held_state in ["none_held", "released", "unknown"] {
                        replies.push(json!({
                            "outcome":"dispatch_outcome_unknown",
                            "effect_status":"effect_indeterminate",
                            "detail":{"reason":reason,"dispatched":true,"step":step,"call":"Page.navigate","held_state":held_state},
                            "remedy":"read the state before retrying",
                        }));
                    }
                }
                for reply in replies {
                    assert_eq!(
                        plane
                            .finish_reply(definition.name, reply.clone())
                            .unwrap_or_else(|error| panic!(
                                "{} was withheld: {error}",
                                definition.name
                            )),
                        reply
                    );
                }
            }
            let reason =
                json!({"outcome":"target_busy","detail":{"reason":"legacy_free_form_reason"}});
            assert_eq!(
                plane.finish_reply(definition.name, reason.clone()).unwrap(),
                reason
            );
        }
        assert!(plane.result_schema_findings().is_empty());
    }

    #[test]
    fn bounded_browser_vocabulary_is_closed_and_preserves_legacy_contracts() {
        let plane =
            BrowserPlane::new().with_result_schema_enforcement(ResultSchemaEnforcement::Withhold);
        for definition in browser_tool_definitions() {
            for (field, value) in [
                ("dispatched", json!("false")),
                ("step", json!("settle")),
                ("step", json!("egress")),
                ("call", json!(true)),
                ("held_state", json!("held")),
                ("reason", json!(false)),
                ("misspelled_field", json!(true)),
            ] {
                let mut reply = json!({"outcome":"dispatch_outcome_unknown", "effect_status":"effect_indeterminate", "detail":{}});
                reply["detail"][field] = value;
                assert!(
                    plane.finish_reply(definition.name, reply).is_err(),
                    "{} accepted invalid {field}",
                    definition.name
                );
            }
            let reply = json!({"outcome":"target_busy","detail":{},"misspelled_field":true});
            assert!(plane.finish_reply(definition.name, reply).is_err());
        }
        let mut legacy = declared_navigate_reply();
        legacy["misspelled_field"] = json!(true);
        assert!(plane.finish_reply(NAVIGATE, legacy).is_err());
        assert!(plane
            .finish_reply(NAVIGATE, json!({"outcome":"ok"}))
            .is_err());
        let context = declared_navigate_reply()["context"].clone();
        for (outcome, detail) in [
            (
                "command_timeout",
                json!({"step":"Input.dispatchKeyEvent","command_sent":true,"reason_code":"command_deadline_expired"}),
            ),
            (
                "internal_error",
                json!({"step":"Runtime.callFunctionOn","reason_code":"cdp_failure"}),
            ),
            (
                "authorization_denied",
                json!({"reason":"legacy_free_form_reason"}),
            ),
        ] {
            let legacy = json!({"outcome":outcome,"context":context,"detail":detail});
            assert_eq!(
                plane.finish_reply(NAVIGATE, legacy.clone()).unwrap(),
                legacy
            );
        }
    }

    #[test]
    fn browser_bounded_call_vocabulary_is_frozen() {
        let definitions = browser_tool_definitions();
        assert_eq!(definitions.len(), 17);
        for definition in definitions {
            let terminal = &definition.result_schema["anyOf"][1];
            assert_eq!(terminal["additionalProperties"], false);
            assert_eq!(
                terminal["properties"]["outcome"]["enum"],
                json!([
                    "action_deadline_exceeded",
                    "dispatch_outcome_unknown",
                    "target_busy",
                    "blocking_capacity_exhausted",
                ])
            );
            let detail = &terminal["properties"]["detail"];
            assert_eq!(detail["additionalProperties"], false);
            assert_eq!(
                detail["properties"]["step"]["enum"],
                json!([
                    "admission",
                    "queue",
                    "consent",
                    "preflight",
                    "dispatch",
                    "release",
                ])
            );
            assert_eq!(
                detail["properties"]["held_state"]["enum"],
                json!(["none_held", "released", "unknown"])
            );
            assert_eq!(detail["properties"]["reason"]["type"], "string");
            assert!(detail["properties"]["reason"].get("enum").is_none());
            assert_eq!(
                terminal["properties"]["effect_status"]["enum"],
                json!([
                    "effect_observed",
                    "no_effect_observed",
                    "effect_indeterminate"
                ])
            );
        }
    }

    #[test]
    fn browser_control_stage_enums_include_custody_held() {
        let plane =
            BrowserPlane::new().with_result_schema_enforcement(ResultSchemaEnforcement::Withhold);
        for name in [
            crate::browser_session::BROWSER_STATUS,
            crate::browser_session::BROWSER_CLOSE,
        ] {
            let definition = browser_tool_definitions()
                .into_iter()
                .find(|definition| definition.name == name)
                .unwrap();
            assert_eq!(
                definition.result_schema["anyOf"][0]["properties"]["stage"]["enum"],
                json!([
                    "reap",
                    "record_terminalization",
                    "custody_release",
                    "disposable_delete",
                    "crash_reports_delete",
                    "custody_held",
                    "browser_session_lock",
                ])
            );
            let reply = json!({"outcome":"cleanup_failure","stage":"custody_held"});
            assert_eq!(plane.finish_reply(name, reply.clone()).unwrap(), reply);
        }
    }

    #[test]
    fn bounded_results_leave_advertised_browser_use_bytes_unchanged() {
        let names = crate::tool_provider::browser_tools()
            .into_iter()
            .map(|tool| tool.name)
            .collect::<Vec<_>>();
        let tool = crate::flat_tools::browser_tool(&names).unwrap();
        assert!(tool.schema.get("anyOf").is_none());
        let bytes = serde_json::to_vec(
            &json!({"name":tool.name,"description":tool.description,"input_schema":tool.schema}),
        )
        .unwrap();
        // Same frozen digest as tool_provider's definition pin: the result-schema
        // branches must never change the bytes agents are shown.
        assert_eq!(
            crate::manifest::sha256_hex(&bytes),
            "ad985c7d39e899cb76edf29d4879ae0b285ff8df11133b5f433f3a8b68e49e78"
        );
    }

    /// A composite keyword on the WRONG composite type is refused, not ignored.
    ///
    /// Two checks already stood here and neither covered this: an unknown
    /// keyword is refused by name, and an object-or-array keyword on a SCALAR
    /// is refused. What fell between them is a known keyword valid for one
    /// composite type sitting on the other -- `required` on an array, `items`
    /// on an object. Enforcement reads only the keywords it knows for the type
    /// in hand, so those constrain nothing while reading, to their author, as
    /// constraints. These schemas are built by `json!` in this file, so nothing
    /// else would catch it.
    ///
    /// Both arms on purpose: the shipped schemas pass, which says the check can
    /// come back clean, and the gap case fails, which says it is looking. The
    /// nullable arm keeps the check honest about multi-type schemas, which the
    /// loader permits for SCALARS ONLY -- it refuses `array` or `object` inside
    /// a list of more than one -- so reading the first type is the whole rule
    /// and a nullable string must still pass.
    #[test]
    fn a_composite_keyword_on_the_wrong_composite_type_is_refused() {
        validate_runtime_result_schema(&navigate_result_schema(), "$")
            .expect("the shipped navigate schema uses only applicable keywords");

        let required_on_an_array = json!({
            "type": "array",
            "items": { "type": "string" },
            "required": ["outcome"],
        });
        let error = validate_runtime_result_schema(&required_on_an_array, "$")
            .expect_err("required on an array is refused rather than ignored");
        assert!(
            matches!(
                error,
                CapabilityResultValidationError::MalformedArtifact(ref message)
                    if message.contains("required") && message.contains("does not apply")
            ),
            "expected the refusal to name the keyword, got {error:?}"
        );

        let items_on_an_object = json!({
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": false,
            "items": { "type": "string" },
        });
        validate_runtime_result_schema(&items_on_an_object, "$")
            .expect_err("items on an object is refused");

        let nullable_string = json!({
            "type": ["string", "null"],
            "description": "a value the page may not have",
        });
        validate_runtime_result_schema(&nullable_string, "$")
            .expect("a nullable string carrying only scalar keywords is accepted");
    }

    #[test]
    fn browser_result_schema_withholds_undeclared_and_wrong_typed_reply_fields() {
        let plane =
            BrowserPlane::new().with_result_schema_enforcement(ResultSchemaEnforcement::Withhold);
        let mut undeclared = declared_navigate_reply();
        undeclared
            .as_object_mut()
            .expect("navigate reply is an object")
            .insert("not_declared".into(), json!(true));
        let error = plane
            .finish_reply(NAVIGATE, undeclared)
            .expect_err("an undeclared reply field is withheld");
        assert!(matches!(
            error,
            CapabilityResultValidationError::ReplyViolations { ref violations, .. }
                if violations == &[CapabilityResultViolation::UndeclaredProperty {
                    path: "$.not_declared".into()
                }]
        ));
        assert_eq!(
            RESULT_SCHEMA_VIOLATION_CODE,
            "computer_result_schema_violation"
        );

        let mut wrong_type = declared_navigate_reply();
        wrong_type
            .as_object_mut()
            .expect("navigate reply is an object")
            .insert("http_status".into(), json!("200"));
        let error = plane
            .finish_reply(NAVIGATE, wrong_type)
            .expect_err("a wrong-typed reply field is withheld");
        assert!(matches!(
            error,
            CapabilityResultValidationError::ReplyViolations { ref violations, .. }
                if violations == &[CapabilityResultViolation::ExpectedType {
                    path: "$.http_status".into(),
                    expected: "integer".into()
                }]
        ));
    }

    #[tokio::test]
    async fn wait_consumes_late_event_before_session_state() {
        let plane = BrowserPlane::new();
        let identity = identity();
        plane
            .queue_event(&identity, LateEvent::DownloadBlocked)
            .await;
        let result = plane
            .dispatch(
                &identity,
                BrowserCapability::WaitFor,
                &json!({"deadline_ms":0}),
            )
            .await;
        assert_eq!(result["outcome"], "unsupported_download");
        assert_eq!(
            result["remedy"],
            "choose an in-page action that does not start a download"
        );
    }
}

/// Schema for a shared resource-busy refusal; resource names and future holder
/// kinds are open strings.
pub(crate) fn resource_busy_detail_schema() -> Value {
    json!({
        "type":"object",
        "properties":{
            "resource":{"type":"string"},
            "holder":{
                "type":"object",
                "properties":{"kind":{"type":"string"},"flow_id":{"type":"string"}},
                "required":["kind"],"additionalProperties":false
            },
            "since_ms":{"type":"integer"},
            "retry_after_ms":{"type":"integer"}
        },
        "required":["resource","holder","since_ms","retry_after_ms"],
        "additionalProperties":false
    })
}

#[cfg(test)]
mod resource_busy_schema_tests {
    use super::*;

    #[test]
    fn resource_busy_detail_alternatives_are_closed_and_enforced() {
        let schema = json!({"anyOf":[invalid_request_detail_result_schema(), resource_busy_detail_schema()]});
        validate_runtime_result_schema(&schema, "detail").unwrap();
        for detail in [
            json!({"field":"url","reason_code":"missing_field"}),
            serde_json::to_value(cortexkit_resource_busy::ResourceBusy::new(
                "browser_profile",
                cortexkit_resource_busy::Holder::head(),
                1,
                2,
            ))
            .unwrap(),
        ] {
            let mut errors = Vec::new();
            collect_result_violations(&schema, &detail, "$", &mut errors);
            assert!(errors.is_empty(), "{errors:?}");
        }
        for detail in [
            json!({}),
            json!({"field":"url","reason_code":"missing_field","extra":true}),
            json!({"resource":"browser_profile","holder":{"kind":"head"},"since_ms":1}),
        ] {
            let mut errors = Vec::new();
            collect_result_violations(&schema, &detail, "$", &mut errors);
            assert!(!errors.is_empty(), "undeclared detail accepted: {detail}");
        }
    }

    #[test]
    fn resource_busy_detail_alternatives_reject_malformed_schema_branches() {
        for schema in [
            json!({"anyOf":[]}),
            json!({"anyOf":[{"type":"object"}]}),
            json!({"anyOf":[{"type":"string"}],"type":"string"}),
        ] {
            assert!(
                validate_runtime_result_schema(&schema, "detail").is_err(),
                "{schema}"
            );
        }
    }
}

#[cfg(test)]
mod agent_enforcement_tests;
#[cfg(test)]
mod codemode_tests;
