use std::cmp;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use serde_json::{Map, Value};

use crate::browser::geometry::{self, Quad};
use crate::browser::Tracker;
use crate::browser_launch_readiness::{CdpPipeIo, PipeRead};
use crate::browser_session::{
    BrowserClickOutcome, BrowserClickPosition, BrowserInputEvent, BrowserJavaScriptDialog,
    ClickDriveError, ClickNavigation, ClickPointDriveError, JavaScriptDialogResponse,
    NavigationDriveError, NavigationWait, ViewportRefusal,
};
use crate::cdp::{Attachment, CdpEvent, CdpFrameDecoder, CdpResponse, CdpTransport, IdentityMap};
use crate::classification::{
    self, AssociatedFormControlInput, ClassificationUnavailable, ElementClassificationInput,
    NodeIdentityInput, NonTypeClassificationInput, NonTypeClassificationRecord, TargetKind,
};
use crate::coordinate::{InputRect, TransformInputs, ViewportObservation};
use crate::snapshot_store::{
    truncate_ax_field, AxRecord, BackendNodeIdentity, RefRecord, SnapshotKind, SnapshotRef,
    MAX_NAME_BYTES, MAX_REFS, MAX_ROLE_BYTES, MAX_VALUE_BYTES,
};

const READ_CHUNK_BYTES: usize = 64 * 1024;

/// How long after a click's release is acknowledged to watch for the main
/// frame starting a navigation before reporting that none was observed.
///
/// Measured against Chrome 153 headless on macOS (2026-09-25), clicking
/// cross-origin-redirect, fragment, iframe, unresolvable-host and 204 links
/// on a local server: the main frame's `Page.frameRequestedNavigation` arrived
/// before the release acknowledgement in every run (18 to 114 ms before it),
/// and a fragment's `Page.navigatedWithinDocument` at most 28 ms after. The window
/// catches a start the renderer reports late on a loaded machine without
/// making every non-navigating click wait long.
const CLICK_NAVIGATION_WINDOW: Duration = Duration::from_millis(100);
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const MAX_AX_NODES: usize = MAX_REFS;
const MAX_AX_DEPTH: usize = 64;

/// Standard-tier vision long-edge cap, in pixels.
///
/// Claude's standard tier uses 1568 for two different limits: the longest
/// side of an image, and the visual-token budget where an image costs
/// `ceil(width / 28) * ceil(height / 28)` tokens. The high-resolution tier
/// (Claude 4.7 and later) allows 2576 px and 4784 tokens. This module cannot
/// know which model will read a capture. Undershooting costs a high-resolution
/// consumer some detail; overshooting makes the API downscale again, so the
/// model produces coordinates in a smaller space than we report. That is the
/// mismatch `click_point` exists to prevent. Standard is the bound that keeps
/// every consumer correct.
pub const VISION_LONG_EDGE_PX: u32 = 1568;

/// Pixel size of one visual-token patch.
const VISION_PATCH_PX: u32 = 28;

/// Standard-tier visual-token cap. Equal to [`VISION_LONG_EDGE_PX`] on the
/// standard tier; a distinct constant because an image can satisfy the edge
/// limit while still costing more tokens than this.
const VISION_TOKEN_CAP: u32 = 1568;

/// Page data extracted by the session-owned CDP driver.
///
/// The caller retains this separately from the driver so the pipe and request
/// correlator remain owned by the browser session rather than by snapshot state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserSnapshotObservation {
    pub records: Vec<AxRecord>,
    pub dom_text: Option<String>,
    pub refs: Vec<RefRecord>,
    pub ax_truncated: bool,
    pub refs_truncated: bool,
}

/// Browser-reported image bytes and geometry bracketing one visual viewport capture.
#[derive(Debug, Clone, PartialEq)]
pub struct BrowserScreenshotObservation {
    pub image_png_b64: String,
    pub before: ViewportObservation,
    pub after: ViewportObservation,
    pub invalidation_observed: bool,
}

struct CssVisualViewport {
    rect: InputRect,
    scale: f64,
    page_x: Option<f64>,
    page_y: Option<f64>,
}

/// Scale Chrome should apply to a visual-viewport clip so the returned bitmap
/// is the largest aspect-preserving size that fits both standard-tier vision
/// limits: the long-edge cap and the token cap.
///
/// Chrome multiplies `clip.scale` by the device scale factor, so this value is
/// `target / (css * device_scale_factor)` for either dimension. `None` means
/// the unclipped capture already fits both limits, or the caller asked for
/// `full`.
pub fn screenshot_clip_scale(
    width_css: f64,
    height_css: f64,
    device_scale_factor: f64,
    full: bool,
) -> Option<f64> {
    if full {
        return None;
    }
    if !width_css.is_finite()
        || width_css <= 0.0
        || !height_css.is_finite()
        || height_css <= 0.0
        || !device_scale_factor.is_finite()
        || device_scale_factor <= 0.0
    {
        return None;
    }
    let native_width = width_css * device_scale_factor;
    let native_height = height_css * device_scale_factor;
    let target_width = max_vision_width_px(native_width, native_height);
    if target_width <= 0.0 || target_width >= native_width {
        None
    } else {
        Some(target_width / native_width)
    }
}

/// Largest aspect-preserving width, in pixels, that satisfies both
/// standard-tier vision limits.
///
/// Tokens are counted on a grid of [`VISION_PATCH_PX`] squares, so feasible
/// sizes are `patch_w` by `patch_h` rectangles with `patch_w * patch_h` at
/// most [`VISION_TOKEN_CAP`] and each side at most [`VISION_LONG_EDGE_PX`].
/// The largest size on the native aspect line is the right edge of the best
/// such rectangle.
fn max_vision_width_px(native_width: f64, native_height: f64) -> f64 {
    let patch = f64::from(VISION_PATCH_PX);
    let max_patches = VISION_LONG_EDGE_PX / VISION_PATCH_PX;
    let aspect = native_height / native_width;
    let mut best_width: f64 = 0.0;
    for patch_w in 1..=max_patches {
        for patch_h in 1..=max_patches {
            if patch_w.saturating_mul(patch_h) > VISION_TOKEN_CAP {
                continue;
            }
            // Half-open pixel box for this patch pair: width in
            // ((patch_w-1)*patch, patch_w*patch], same for height. Intersect
            // the aspect line with that box and keep the largest width.
            let width_lo =
                (f64::from(patch_w - 1) * patch).max(f64::from(patch_h - 1) * patch / aspect);
            let width_hi = (f64::from(patch_w) * patch).min(f64::from(patch_h) * patch / aspect);
            if width_hi > width_lo {
                best_width = best_width.max(width_hi);
            }
        }
    }
    best_width.min(native_width)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawAxNode {
    node_id: String,
    ignored: bool,
    role: String,
    name: String,
    value: Option<String>,
    child_ids: Vec<String>,
    backend_node_id: Option<u64>,
    frame_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawDomNode {
    node_id: u64,
    parent_id: Option<u64>,
    backend_node_id: u64,
    local_name: String,
    attributes: HashMap<String, String>,
    assigned_slot_backend_node_id: Option<u64>,
}

struct PendingAxNode {
    node: Option<RawAxNode>,
    node_id: String,
    depth: usize,
    frame_path: Vec<String>,
    ancestors: HashSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AttachedTarget {
    target_id: String,
    session_id: String,
    context_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingJavaScriptDialog {
    session_id: String,
    dialog_type: String,
}

/// Owns every CDP write, frame decoder, and request correlator for one browser.
/// Keeping these together prevents a lifecycle command and a navigation command
/// from assigning competing request ids or interleaving frames on the pipe.
pub struct CdpNavigationDriver<IO> {
    pipe: IO,
    transport: CdpTransport,
    decoder: CdpFrameDecoder,
    identities: IdentityMap,
    attachment: Option<AttachedTarget>,
    pending_responses: HashMap<u64, CdpResponse>,
    pending_javascript_dialogs: VecDeque<PendingJavaScriptDialog>,
    read_buffer: Vec<u8>,
}

impl<IO: CdpPipeIo> CdpNavigationDriver<IO> {
    pub fn new(pipe: IO, mut transport: CdpTransport, decoder: CdpFrameDecoder) -> Self {
        // Readiness can observe browser-wide startup events before this route has
        // attached a target. They have no route identity and must not remain in
        // the established session's bounded event queue.
        while transport.pop_event().is_some() {}
        Self {
            pipe,
            transport,
            decoder,
            identities: IdentityMap::new(),
            attachment: None,
            pending_responses: HashMap::new(),
            pending_javascript_dialogs: VecDeque::new(),
            read_buffer: vec![0; READ_CHUNK_BYTES],
        }
    }

    pub fn present(
        &mut self,
        context_key: &str,
        deadline_ms: u64,
    ) -> Result<(), NavigationDriveError> {
        let mut clock = SystemNavigationClock;
        let deadline = clock
            .now()
            .checked_add(Duration::from_millis(deadline_ms))
            .ok_or(NavigationDriveError::CdpFailure)?;
        self.ensure_attached(context_key, deadline, &mut clock)?;
        let attachment = self
            .attachment
            .clone()
            .ok_or(NavigationDriveError::CdpFailure)?;

        let fronted = self.command_response(
            "Page.bringToFront",
            None,
            Some(attachment.session_id),
            deadline,
            None,
            None,
            &mut clock,
        )?;
        if let Some(error) = fronted.error {
            return Err(NavigationDriveError::CommandFailed {
                error_text: cdp_error_text(error),
            });
        }

        // Page.bringToFront selects the tab inside Chrome. On macOS the window
        // server may still keep another application's window above Chrome, so
        // activate the owning target as the second, browser-wide nudge.
        let mut params = Map::new();
        params.insert("targetId".into(), Value::String(attachment.target_id));
        let activated = self.command_response(
            "Target.activateTarget",
            Some(params),
            None,
            deadline,
            None,
            None,
            &mut clock,
        )?;
        if let Some(error) = activated.error {
            return Err(NavigationDriveError::CommandFailed {
                error_text: cdp_error_text(error),
            });
        }
        Ok(())
    }

    pub fn cookie_names_for_origin(
        &mut self,
        context_key: &str,
        origin: &str,
        deadline_ms: u64,
    ) -> Result<BTreeSet<String>, NavigationDriveError> {
        let mut clock = SystemNavigationClock;
        let deadline = clock
            .now()
            .checked_add(Duration::from_millis(deadline_ms))
            .ok_or(NavigationDriveError::CdpFailure)?;
        self.ensure_attached(context_key, deadline, &mut clock)?;
        let attachment = self
            .attachment
            .clone()
            .ok_or(NavigationDriveError::CdpFailure)?;
        let mut params = Map::new();
        params.insert(
            "urls".into(),
            Value::Array(vec![Value::String(origin.to_string())]),
        );
        let result = self.command(
            "Network.getCookies",
            Some(params),
            Some(attachment.session_id),
            deadline,
            None,
            &mut clock,
        )?;
        let cookies = result
            .get("cookies")
            .and_then(Value::as_array)
            .ok_or(NavigationDriveError::CdpFailure)?;
        cookies
            .iter()
            .map(|cookie| {
                cookie
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .ok_or(NavigationDriveError::CdpFailure)
            })
            .collect()
    }

    /// The request `Cookie:` header Chrome would send to `url`, in the order
    /// CDP returns the cookies. Only `browser.capture_login` reads values, and
    /// only through the capture browser; the header type cannot be formatted
    /// or serialized, so the value cannot leave through an error or a reply.
    pub fn cookie_request_header_for_url(
        &mut self,
        context_key: &str,
        url: &str,
        deadline_ms: u64,
    ) -> Result<
        Result<crate::login_capture::CookieHeader, crate::login_capture::CookieHeaderError>,
        NavigationDriveError,
    > {
        let mut clock = SystemNavigationClock;
        let deadline = clock
            .now()
            .checked_add(Duration::from_millis(deadline_ms))
            .ok_or(NavigationDriveError::CdpFailure)?;
        self.ensure_attached(context_key, deadline, &mut clock)?;
        let attachment = self
            .attachment
            .clone()
            .ok_or(NavigationDriveError::CdpFailure)?;
        let mut params = Map::new();
        params.insert(
            "urls".into(),
            Value::Array(vec![Value::String(url.to_string())]),
        );
        let result = self.command(
            "Network.getCookies",
            Some(params),
            Some(attachment.session_id),
            deadline,
            None,
            &mut clock,
        )?;
        let cookies = result
            .get("cookies")
            .and_then(Value::as_array)
            .ok_or(NavigationDriveError::CdpFailure)?;
        let pairs = cookies
            .iter()
            .map(|cookie| {
                Some((
                    cookie.get("name").and_then(Value::as_str)?,
                    cookie.get("value").and_then(Value::as_str)?,
                ))
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(NavigationDriveError::CdpFailure)?;
        Ok(crate::login_capture::CookieHeader::from_pairs(pairs))
    }

    pub fn main_frame_url(
        &mut self,
        context_key: &str,
        deadline_ms: u64,
    ) -> Result<String, NavigationDriveError> {
        let mut clock = SystemNavigationClock;
        self.main_frame_url_with_clock(context_key, deadline_ms, &mut clock)
    }

    pub fn has_credential_field(
        &mut self,
        context_key: &str,
        deadline_ms: u64,
    ) -> Result<bool, NavigationDriveError> {
        let mut clock = SystemNavigationClock;
        let observation = self.snapshot_with_clock(
            context_key,
            SnapshotKind::Ax,
            deadline_ms,
            Some((0, "null")),
            &mut clock,
        )?;
        Ok(observation.refs.iter().any(|reference| {
            reference
                .classification
                .as_deref()
                .is_ok_and(NonTypeClassificationRecord::is_credential_field)
        }))
    }

    pub fn navigate(
        &mut self,
        context_key: &str,
        url: &str,
        wait: NavigationWait,
        deadline_ms: u64,
        tracker: &mut Tracker,
    ) -> Result<(), NavigationDriveError> {
        let mut clock = SystemNavigationClock;
        self.navigate_with_clock(context_key, url, wait, deadline_ms, tracker, &mut clock)
    }

    #[cfg(test)]
    pub(crate) fn navigate_for_test<C: NavigationClock>(
        &mut self,
        context_key: &str,
        url: &str,
        wait: NavigationWait,
        deadline_ms: u64,
        tracker: &mut Tracker,
        clock: &mut C,
    ) -> Result<(), NavigationDriveError> {
        self.navigate_with_clock(context_key, url, wait, deadline_ms, tracker, clock)
    }

    pub fn snapshot(
        &mut self,
        context_key: &str,
        mode: SnapshotKind,
        deadline_ms: u64,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        let mut clock = SystemNavigationClock;
        self.snapshot_with_clock(context_key, mode, deadline_ms, None, &mut clock)
    }

    pub fn snapshot_classified(
        &mut self,
        context_key: &str,
        mode: SnapshotKind,
        document_epoch: u64,
        current_origin: &str,
        deadline_ms: u64,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        let mut clock = SystemNavigationClock;
        self.snapshot_with_clock(
            context_key,
            mode,
            deadline_ms,
            Some((document_epoch, current_origin)),
            &mut clock,
        )
    }

    pub fn screenshot(
        &mut self,
        context_key: &str,
        document_epoch: u64,
        deadline_ms: u64,
        full: bool,
    ) -> Result<BrowserScreenshotObservation, NavigationDriveError> {
        let mut clock = SystemNavigationClock;
        self.screenshot_with_clock(context_key, document_epoch, deadline_ms, full, &mut clock)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn click_classified(
        &mut self,
        context_key: &str,
        identity: &BackendNodeIdentity,
        document_epoch: u64,
        current_origin: &str,
        expected: Option<&NonTypeClassificationRecord>,
        deadline_ms: u64,
        input_dispatched: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        let mut clock = SystemNavigationClock;
        self.click_with_clock(
            context_key,
            identity,
            deadline_ms,
            input_dispatched,
            Some((document_epoch, current_origin, expected)),
            &mut clock,
        )
    }

    /// Dispatch a coordinate click through this driver's owned CDP session.
    pub fn click_point(
        &mut self,
        context_key: &str,
        position: BrowserClickPosition,
        deadline_ms: u64,
        input_dispatched: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickPointDriveError> {
        let mut clock = SystemNavigationClock;
        self.click_point_with_clock(
            context_key,
            position,
            deadline_ms,
            input_dispatched,
            &mut clock,
        )
    }

    #[cfg(test)]
    fn click_for_test<C: NavigationClock>(
        &mut self,
        context_key: &str,
        identity: &BackendNodeIdentity,
        deadline_ms: u64,
        input_dispatched: &mut dyn FnMut(BrowserInputEvent),
        clock: &mut C,
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        self.click_with_clock(
            context_key,
            identity,
            deadline_ms,
            input_dispatched,
            None,
            clock,
        )
    }

    #[cfg(test)]
    fn snapshot_for_test<C: NavigationClock>(
        &mut self,
        context_key: &str,
        mode: SnapshotKind,
        deadline_ms: u64,
        clock: &mut C,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        self.snapshot_with_clock(context_key, mode, deadline_ms, None, clock)
    }

    #[cfg(test)]
    fn screenshot_for_test<C: NavigationClock>(
        &mut self,
        context_key: &str,
        document_epoch: u64,
        deadline_ms: u64,
        full: bool,
        clock: &mut C,
    ) -> Result<BrowserScreenshotObservation, NavigationDriveError> {
        self.screenshot_with_clock(context_key, document_epoch, deadline_ms, full, clock)
    }

    #[cfg(test)]
    fn classify_click_for_test<C: NavigationClock>(
        &mut self,
        context_key: &str,
        identity: &BackendNodeIdentity,
        document_epoch: u64,
        document_url: &str,
        deadline_ms: u64,
        clock: &mut C,
    ) -> Result<Result<NonTypeClassificationRecord, ClassificationUnavailable>, NavigationDriveError>
    {
        let deadline = clock
            .now()
            .checked_add(Duration::from_millis(deadline_ms))
            .ok_or(NavigationDriveError::CdpFailure)?;
        self.ensure_attached(context_key, deadline, clock)?;
        self.classify_click_before(
            context_key,
            identity,
            document_epoch,
            document_url,
            deadline,
            clock,
        )
    }

    /// Classify one click target. The outer error is a transport failure that
    /// ends the action; the inner one is a named reason the target could not be
    /// classified, which authorization treats as the strongest hazard.
    fn classify_click_before<C: NavigationClock>(
        &mut self,
        context_key: &str,
        identity: &BackendNodeIdentity,
        document_epoch: u64,
        document_url: &str,
        deadline: Instant,
        clock: &mut C,
    ) -> Result<Result<NonTypeClassificationRecord, ClassificationUnavailable>, NavigationDriveError>
    {
        let attachment = self
            .attachment
            .clone()
            .filter(|attachment| {
                attachment.context_key == context_key && attachment.target_id == identity.target_id
            })
            .ok_or(NavigationDriveError::CdpFailure)?;
        let current_origin = match document_origin(document_url) {
            Ok(origin) => origin,
            Err(reason) => return Ok(Err(reason)),
        };
        let nodes = self.flattened_dom_nodes_before(&attachment, deadline, clock)?;
        Ok(nodes.and_then(|nodes| {
            build_non_type_classification(&nodes, identity, document_epoch, &current_origin)
        }))
    }

    fn flattened_dom_nodes_before<C: NavigationClock>(
        &mut self,
        attachment: &AttachedTarget,
        deadline: Instant,
        clock: &mut C,
    ) -> Result<Result<Vec<RawDomNode>, ClassificationUnavailable>, NavigationDriveError> {
        let enabled = self.command_response(
            "DOM.enable",
            None,
            Some(attachment.session_id.clone()),
            deadline,
            None,
            None,
            clock,
        )?;
        if enabled.error.is_some() || enabled.result.is_none() {
            return Ok(Err(ClassificationUnavailable::DomEnableRefused));
        }
        let mut params = Map::new();
        params.insert("depth".into(), Value::Number((-1).into()));
        params.insert("pierce".into(), Value::Bool(true));
        let response = self.command_response(
            "DOM.getFlattenedDocument",
            Some(params),
            Some(attachment.session_id.clone()),
            deadline,
            None,
            None,
            clock,
        )?;
        if response.error.is_some() {
            return Ok(Err(ClassificationUnavailable::FlattenedDocumentRefused));
        }
        Ok(response
            .result
            .as_ref()
            .ok_or(ClassificationUnavailable::FlattenedNodesMissing)
            .and_then(parse_flattened_dom_nodes))
    }

    fn click_with_clock<C: NavigationClock>(
        &mut self,
        context_key: &str,
        identity: &BackendNodeIdentity,
        deadline_ms: u64,
        input_dispatched: &mut dyn FnMut(BrowserInputEvent),
        revalidation: Option<(u64, &str, Option<&NonTypeClassificationRecord>)>,
        clock: &mut C,
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        let deadline = clock
            .now()
            .checked_add(Duration::from_millis(deadline_ms))
            .ok_or(ClickDriveError::Navigation(
                NavigationDriveError::CdpFailure,
            ))?;
        self.ensure_attached(context_key, deadline, clock)
            .map_err(ClickDriveError::Navigation)?;
        let attachment = self
            .attachment
            .clone()
            .filter(|attachment| {
                attachment.context_key == context_key && attachment.target_id == identity.target_id
            })
            .ok_or(ClickDriveError::NoPosition)?;

        // Resolve once before scrolling so a detached or geometry-less ref keeps
        // the existing no-position refusal. The post-scroll fetch below is the
        // only coordinate that may reach hit testing or input dispatch.
        self.content_quad_position(
            identity.backend_node_id,
            &attachment.session_id,
            deadline,
            clock,
        )?;

        let mut scroll_params = Map::new();
        scroll_params.insert(
            "backendNodeId".into(),
            Value::Number(identity.backend_node_id.into()),
        );
        let scroll = self
            .command_response(
                "DOM.scrollIntoViewIfNeeded",
                Some(scroll_params),
                Some(attachment.session_id.clone()),
                deadline,
                None,
                None,
                clock,
            )
            .map_err(ClickDriveError::Navigation)?;
        if scroll.error.is_some() {
            return Err(ClickDriveError::NoPosition);
        }

        let position = self.content_quad_position(
            identity.backend_node_id,
            &attachment.session_id,
            deadline,
            clock,
        )?;
        let viewport = self
            .read_css_visual_viewport(&attachment.session_id, deadline, clock)
            .map(|visual| visual.rect)
            .map_err(ClickDriveError::Navigation)?;
        match geometry::require_point_in_viewport(position.x_css, position.y_css, viewport) {
            Ok(()) => {}
            Err(geometry::GeometryError::OutsideViewport) => {
                return Err(ClickDriveError::OutsideViewportAfterScroll(
                    ViewportRefusal { position, viewport },
                ));
            }
            Err(_) => {
                return Err(ClickDriveError::Navigation(
                    NavigationDriveError::CdpFailure,
                ));
            }
        }

        let hit_x = hit_test_coordinate(position.x_css)?;
        let hit_y = hit_test_coordinate(position.y_css)?;
        let mut hit_params = Map::new();
        hit_params.insert("x".into(), Value::Number(hit_x.into()));
        hit_params.insert("y".into(), Value::Number(hit_y.into()));
        hit_params.insert("includeUserAgentShadowDOM".into(), Value::Bool(true));
        let hit_response = self
            .command_response(
                "DOM.getNodeForLocation",
                Some(hit_params),
                Some(attachment.session_id.clone()),
                deadline,
                None,
                None,
                clock,
            )
            .map_err(ClickDriveError::Navigation)?;
        if hit_response.error.is_some() {
            return Err(ClickDriveError::NoPosition);
        }
        let hit_result = hit_response.result.ok_or(ClickDriveError::Navigation(
            NavigationDriveError::CdpFailure,
        ))?;
        let hit_backend_node_id = hit_result
            .get("backendNodeId")
            .and_then(Value::as_u64)
            .filter(|value| *value > 0)
            .ok_or(ClickDriveError::Navigation(
                NavigationDriveError::CdpFailure,
            ))?;
        let hit_frame_id = hit_result
            .get("frameId")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(ClickDriveError::Navigation(
                NavigationDriveError::CdpFailure,
            ))?;
        if hit_frame_id != identity.frame_id {
            return Err(ClickDriveError::NoPosition);
        }
        if hit_backend_node_id != identity.backend_node_id {
            let mut describe_params = Map::new();
            describe_params.insert(
                "backendNodeId".into(),
                Value::Number(identity.backend_node_id.into()),
            );
            describe_params.insert("depth".into(), Value::Number((-1).into()));
            describe_params.insert("pierce".into(), Value::Bool(true));
            let describe_response = self
                .command_response(
                    "DOM.describeNode",
                    Some(describe_params),
                    Some(attachment.session_id.clone()),
                    deadline,
                    None,
                    None,
                    clock,
                )
                .map_err(ClickDriveError::Navigation)?;
            if describe_response.error.is_some() {
                return Err(ClickDriveError::NoPosition);
            }
            let described = describe_response.result.ok_or(ClickDriveError::Navigation(
                NavigationDriveError::CdpFailure,
            ))?;
            if !described_node_contains(&described, hit_backend_node_id)
                .map_err(ClickDriveError::Navigation)?
            {
                return Err(ClickDriveError::NoPosition);
            }
        }

        if let Some((document_epoch, current_origin, expected)) = revalidation {
            let actual = self
                .classify_click_before(
                    context_key,
                    identity,
                    document_epoch,
                    current_origin,
                    deadline,
                    clock,
                )
                .map_err(ClickDriveError::Navigation)?;
            // Any unavailable classification matches an unavailable snapshot:
            // both were authorized as the strongest hazard, so a different
            // reason for the same unknown does not change what was approved.
            if actual.as_ref().ok() != expected {
                return Err(ClickDriveError::ClassificationChanged);
            }
        }

        self.actuate_click(
            context_key,
            &attachment.session_id,
            position,
            deadline,
            deadline_ms,
            input_dispatched,
            clock,
        )
        .map_err(ClickDriveError::Navigation)
    }

    fn click_point_with_clock<C: NavigationClock>(
        &mut self,
        context_key: &str,
        position: BrowserClickPosition,
        deadline_ms: u64,
        input_dispatched: &mut dyn FnMut(BrowserInputEvent),
        clock: &mut C,
    ) -> Result<BrowserClickOutcome, ClickPointDriveError> {
        let deadline = clock
            .now()
            .checked_add(Duration::from_millis(deadline_ms))
            .ok_or(ClickPointDriveError::Navigation(
                NavigationDriveError::CdpFailure,
            ))?;
        self.ensure_attached(context_key, deadline, clock)
            .map_err(ClickPointDriveError::Navigation)?;
        let attachment = self
            .attachment
            .clone()
            .filter(|attachment| attachment.context_key == context_key)
            .ok_or(ClickPointDriveError::Navigation(
                NavigationDriveError::CdpFailure,
            ))?;
        let viewport = self
            .read_css_visual_viewport(&attachment.session_id, deadline, clock)
            .map(|visual| visual.rect)
            .map_err(ClickPointDriveError::Navigation)?;
        match geometry::require_point_in_viewport(position.x_css, position.y_css, viewport) {
            Ok(()) => {}
            Err(geometry::GeometryError::OutsideViewport) => {
                return Err(ClickPointDriveError::OutsideViewport(ViewportRefusal {
                    position,
                    viewport,
                }));
            }
            Err(_) => {
                return Err(ClickPointDriveError::Navigation(
                    NavigationDriveError::CdpFailure,
                ));
            }
        }
        self.actuate_click(
            context_key,
            &attachment.session_id,
            position,
            deadline,
            deadline_ms,
            input_dispatched,
            clock,
        )
        .map_err(ClickPointDriveError::Navigation)
    }

    fn content_quad_position<C: NavigationClock>(
        &mut self,
        backend_node_id: u64,
        session_id: &str,
        deadline: Instant,
        clock: &mut C,
    ) -> Result<BrowserClickPosition, ClickDriveError> {
        let mut params = Map::new();
        params.insert(
            "backendNodeId".into(),
            Value::Number(backend_node_id.into()),
        );
        let response = self
            .command_response(
                "DOM.getContentQuads",
                Some(params),
                Some(session_id.to_string()),
                deadline,
                None,
                None,
                clock,
            )
            .map_err(ClickDriveError::Navigation)?;
        if response.error.is_some() {
            return Err(ClickDriveError::NoPosition);
        }
        let quads = required_content_quads(&response.result.ok_or(ClickDriveError::Navigation(
            NavigationDriveError::CdpFailure,
        ))?)
        .map_err(ClickDriveError::Navigation)?;
        let projection =
            geometry::select_first_eligible(&quads).map_err(|_| ClickDriveError::NoPosition)?;
        Ok(BrowserClickPosition {
            x_css: projection.x_css,
            y_css: projection.y_css,
        })
    }

    fn read_css_visual_viewport<C: NavigationClock>(
        &mut self,
        session_id: &str,
        deadline: Instant,
        clock: &mut C,
    ) -> Result<CssVisualViewport, NavigationDriveError> {
        let metrics = self.command(
            "Page.getLayoutMetrics",
            None,
            Some(session_id.to_string()),
            deadline,
            None,
            clock,
        )?;
        // The undecorated visualViewport field is deprecated and reports device
        // pixels. Input dispatch uses CSS coordinates, so mixing the two makes
        // an offscreen point appear to be inside on scaled displays.
        let visual_viewport = metrics
            .get("cssVisualViewport")
            .and_then(Value::as_object)
            .ok_or(NavigationDriveError::CdpFailure)?;
        let viewport = InputRect::new(
            required_result_number(visual_viewport, "offsetX")?,
            required_result_number(visual_viewport, "offsetY")?,
            required_result_number(visual_viewport, "clientWidth")?,
            required_result_number(visual_viewport, "clientHeight")?,
        );
        let scale = required_result_number(visual_viewport, "scale")?;
        let right = viewport.x_input_css + viewport.width_input_css;
        let bottom = viewport.y_input_css + viewport.height_input_css;
        if viewport.width_input_css <= 0.0
            || viewport.height_input_css <= 0.0
            || !right.is_finite()
            || !bottom.is_finite()
        {
            return Err(NavigationDriveError::CdpFailure);
        }
        // Clip origin is document-relative. offsetX/Y are the visual viewport's
        // offset inside the layout viewport, which is the wrong origin on a
        // scrolled page.
        let page_x = optional_result_number(visual_viewport, "pageX")?;
        let page_y = optional_result_number(visual_viewport, "pageY")?;
        Ok(CssVisualViewport {
            rect: viewport,
            scale,
            page_x,
            page_y,
        })
    }

    /// Dispatch press then release at `position`, then report what the click
    /// did to the main frame. `settle_deadline_ms` bounds the wait for a
    /// navigation the click started, measured from when it was seen to start,
    /// as `browser.navigate` bounds its own.
    #[allow(clippy::too_many_arguments)]
    fn actuate_click<C: NavigationClock>(
        &mut self,
        context_key: &str,
        session_id: &str,
        position: BrowserClickPosition,
        deadline: Instant,
        settle_deadline_ms: u64,
        input_dispatched: &mut dyn FnMut(BrowserInputEvent),
        clock: &mut C,
    ) -> Result<BrowserClickOutcome, NavigationDriveError> {
        // Page events must be enabled before either input dispatch. Arming after a
        // blocked release would leave the first dialog waiting for an answer,
        // and the events that show the click starting a navigation arrive
        // while the input commands are still in flight.
        self.command(
            "Page.enable",
            None,
            Some(session_id.to_string()),
            deadline,
            None,
            clock,
        )?;
        // Network events are what a navigation settles on (in-flight requests
        // reaching quiet) and where the landing document's status comes from.
        self.command(
            "Network.enable",
            None,
            Some(session_id.to_string()),
            deadline,
            None,
            clock,
        )?;

        // Tracked from the press onward: Chrome reports a link click's
        // navigation request before it acknowledges the release.
        let mut tracker = Tracker::default();
        let mut dialogs = Vec::new();
        let mut press_params = mouse_event_params("mousePressed", position);
        press_params.insert("button".into(), Value::String("left".into()));
        press_params.insert("clickCount".into(), Value::Number(1.into()));
        let mut press_dispatched = || input_dispatched(BrowserInputEvent::Press(position));
        let press = self.command_response_handling_javascript_dialogs(
            "Input.dispatchMouseEvent",
            Some(press_params),
            Some(session_id.to_string()),
            deadline,
            Some(&mut press_dispatched),
            &mut dialogs,
            (context_key, &mut tracker),
            clock,
        )?;
        if press.error.is_some() {
            return Err(NavigationDriveError::CdpFailure);
        }

        let mut release_params = mouse_event_params("mouseReleased", position);
        release_params.insert("button".into(), Value::String("left".into()));
        release_params.insert("clickCount".into(), Value::Number(1.into()));
        let mut release_dispatched = || input_dispatched(BrowserInputEvent::Release(position));
        let release = self.command_response_handling_javascript_dialogs(
            "Input.dispatchMouseEvent",
            Some(release_params),
            Some(session_id.to_string()),
            deadline,
            Some(&mut release_dispatched),
            &mut dialogs,
            (context_key, &mut tracker),
            clock,
        )?;
        if release.error.is_some() {
            return Err(NavigationDriveError::CdpFailure);
        }

        let navigation =
            self.observe_click_navigation(context_key, tracker, settle_deadline_ms, clock)?;
        if dialogs.is_empty() {
            Ok(BrowserClickOutcome::Clicked {
                position,
                navigation,
            })
        } else {
            Ok(BrowserClickOutcome::JavaScriptDialogDismissed {
                position,
                dialogs,
                navigation,
            })
        }
    }

    /// Wait up to [`CLICK_NAVIGATION_WINDOW`] for the main frame to start
    /// navigating, and if it does, settle that navigation exactly as
    /// `browser.navigate` settles its own.
    fn observe_click_navigation<C: NavigationClock>(
        &mut self,
        context_key: &str,
        mut tracker: Tracker,
        settle_deadline_ms: u64,
        clock: &mut C,
    ) -> Result<ClickNavigation, NavigationDriveError> {
        let window_end = clock
            .now()
            .checked_add(CLICK_NAVIGATION_WINDOW)
            .ok_or(NavigationDriveError::CdpFailure)?;
        while !tracker.main_frame_navigation_observed()
            && tracker.same_document_url().is_none()
            && clock.now() < window_end
        {
            self.read_turn(None, Some((context_key, &mut tracker)), clock.now())?;
            if tracker.main_frame_navigation_observed() || tracker.same_document_url().is_some() {
                break;
            }
            let remaining = window_end.saturating_duration_since(clock.now());
            clock.sleep(cmp::min(POLL_INTERVAL, remaining));
        }

        if tracker.main_frame_navigation_observed() {
            // The same first token `browser.navigate` records. Placed first
            // because the landing page may already have fired `load` while
            // the input commands were in flight.
            tracker.lifecycle.insert(0, "navigation_started".into());
            let settle_deadline = clock
                .now()
                .checked_add(Duration::from_millis(settle_deadline_ms))
                .ok_or(NavigationDriveError::CdpFailure)?;
            self.settle_navigation(
                context_key,
                &mut tracker,
                settle_deadline,
                Tracker::navigation_ended_without_commit,
                clock,
            )?;
            return Ok(ClickNavigation::MainFrame(Box::new(tracker)));
        }
        if let Some(url) = tracker.same_document_url() {
            return Ok(ClickNavigation::SameDocument {
                url: url.to_string(),
            });
        }
        Ok(ClickNavigation::NoneObserved {
            window_ms: CLICK_NAVIGATION_WINDOW.as_millis() as u64,
        })
    }

    fn screenshot_with_clock<C: NavigationClock>(
        &mut self,
        context_key: &str,
        document_epoch: u64,
        deadline_ms: u64,
        full: bool,
        clock: &mut C,
    ) -> Result<BrowserScreenshotObservation, NavigationDriveError> {
        let deadline = clock
            .now()
            .checked_add(Duration::from_millis(deadline_ms))
            .ok_or(NavigationDriveError::CdpFailure)?;
        self.ensure_attached(context_key, deadline, clock)?;
        let session_id = self
            .attachment
            .as_ref()
            .filter(|attachment| attachment.context_key == context_key)
            .map(|attachment| attachment.session_id.clone())
            .ok_or(NavigationDriveError::CdpFailure)?;

        let (before, page_origin) =
            self.read_viewport_observation(document_epoch, &session_id, deadline, clock)?;
        let mut params = Map::new();
        params.insert("format".into(), Value::String("png".into()));
        params.insert("fromSurface".into(), Value::Bool(true));
        params.insert("captureBeyondViewport".into(), Value::Bool(false));
        if let Some(scale) = screenshot_clip_scale(
            before.transform.width_input_css,
            before.transform.height_input_css,
            before.transform.device_scale_factor,
            full,
        ) {
            // Chrome's clip is document-relative CSS. scale is multiplied by
            // deviceScaleFactor in the compositor, so this value is chosen so
            // the returned bitmap is the largest size that fits both
            // standard-tier vision limits.
            let (page_x, page_y) = page_origin.ok_or(NavigationDriveError::CdpFailure)?;
            let mut clip = Map::new();
            clip.insert("x".into(), json_finite_number(page_x)?);
            clip.insert("y".into(), json_finite_number(page_y)?);
            clip.insert(
                "width".into(),
                json_finite_number(before.transform.width_input_css)?,
            );
            clip.insert(
                "height".into(),
                json_finite_number(before.transform.height_input_css)?,
            );
            clip.insert("scale".into(), json_finite_number(scale)?);
            params.insert("clip".into(), Value::Object(clip));
        }
        let captured = self.command(
            "Page.captureScreenshot",
            Some(params),
            Some(session_id.clone()),
            deadline,
            None,
            clock,
        )?;
        let image_png_b64 = required_result_string(&captured, "data")?;
        let (after, _) =
            self.read_viewport_observation(document_epoch, &session_id, deadline, clock)?;

        Ok(BrowserScreenshotObservation {
            image_png_b64,
            before,
            after,
            invalidation_observed: false,
        })
    }

    fn read_viewport_observation<C: NavigationClock>(
        &mut self,
        document_epoch: u64,
        session_id: &str,
        deadline: Instant,
        clock: &mut C,
    ) -> Result<(ViewportObservation, Option<(f64, f64)>), NavigationDriveError> {
        let visual = self.read_css_visual_viewport(session_id, deadline, clock)?;
        let viewport = visual.rect;
        let visual_viewport_scale = visual.scale;

        let mut params = Map::new();
        params.insert(
            "expression".into(),
            Value::String("window.devicePixelRatio".into()),
        );
        params.insert("returnByValue".into(), Value::Bool(true));
        let evaluated = self.command(
            "Runtime.evaluate",
            Some(params),
            Some(session_id.to_string()),
            deadline,
            None,
            clock,
        )?;
        let remote_object = evaluated
            .get("result")
            .and_then(Value::as_object)
            .ok_or(NavigationDriveError::CdpFailure)?;
        let device_scale_factor = required_result_number(remote_object, "value")?;

        let page_origin = match (visual.page_x, visual.page_y) {
            (Some(page_x), Some(page_y)) => Some((page_x, page_y)),
            _ => None,
        };
        Ok((
            ViewportObservation::new(
                document_epoch,
                TransformInputs::from_values(
                    viewport.x_input_css,
                    viewport.y_input_css,
                    viewport.width_input_css,
                    viewport.height_input_css,
                    device_scale_factor,
                    visual_viewport_scale,
                ),
            ),
            page_origin,
        ))
    }

    fn snapshot_with_clock<C: NavigationClock>(
        &mut self,
        context_key: &str,
        mode: SnapshotKind,
        deadline_ms: u64,
        classification_context: Option<(u64, &str)>,
        clock: &mut C,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        if mode == SnapshotKind::Screenshot {
            return Err(NavigationDriveError::CdpFailure);
        }
        let deadline = clock
            .now()
            .checked_add(Duration::from_millis(deadline_ms))
            .ok_or(NavigationDriveError::CdpFailure)?;
        self.ensure_attached(context_key, deadline, clock)?;
        let attachment = self
            .attachment
            .clone()
            .filter(|attachment| attachment.context_key == context_key)
            .ok_or(NavigationDriveError::CdpFailure)?;

        self.command(
            "Accessibility.enable",
            None,
            Some(attachment.session_id.clone()),
            deadline,
            None,
            clock,
        )?;
        let root_result = self.command(
            "Accessibility.getRootAXNode",
            None,
            Some(attachment.session_id.clone()),
            deadline,
            None,
            clock,
        )?;
        let root = required_ax_node(&root_result, "node")?;
        let session_id = attachment.session_id.clone();
        let mut observation = traverse_ax_tree(
            root,
            &attachment.target_id,
            MAX_AX_NODES,
            MAX_AX_DEPTH,
            |node_id, frame_id| {
                let mut params = Map::new();
                params.insert("id".into(), Value::String(node_id.to_string()));
                if let Some(frame_id) = frame_id {
                    params.insert("frameId".into(), Value::String(frame_id.to_string()));
                }
                let result = self.command(
                    "Accessibility.getChildAXNodes",
                    Some(params),
                    Some(session_id.clone()),
                    deadline,
                    None,
                    clock,
                )?;
                required_ax_nodes(&result)
            },
        )?;

        if let Some((document_epoch, document_url)) = classification_context {
            // One DOM read serves every ref. A failure here leaves each ref
            // with the same named reason rather than failing the snapshot:
            // the refs are still observable, only their form facts are not.
            let projection = document_origin(document_url).and_then(|origin| {
                match self.flattened_dom_nodes_before(&attachment, deadline, clock) {
                    Ok(nodes) => nodes.map(|nodes| (origin, nodes)),
                    Err(_) => Err(ClassificationUnavailable::DomReadFailed),
                }
            });
            for reference in &mut observation.refs {
                let Some(identity) = reference.backend_identity.as_ref() else {
                    continue;
                };
                reference.classification = match &projection {
                    Ok((origin, nodes)) => {
                        build_non_type_classification(nodes, identity, document_epoch, origin)
                            .map(Box::new)
                    }
                    Err(reason) => Err(reason.clone()),
                };
            }
        }

        if mode == SnapshotKind::DomFull {
            let mut params = Map::new();
            params.insert("depth".into(), Value::Number(0.into()));
            params.insert("pierce".into(), Value::Bool(true));
            let document = self.command(
                "DOM.getDocument",
                Some(params),
                Some(attachment.session_id.clone()),
                deadline,
                None,
                clock,
            )?;
            let node_id = document
                .get("root")
                .and_then(Value::as_object)
                .and_then(|root| root.get("nodeId"))
                .and_then(Value::as_u64)
                .filter(|node_id| *node_id > 0)
                .ok_or(NavigationDriveError::CdpFailure)?;
            let mut params = Map::new();
            params.insert("nodeId".into(), Value::Number(node_id.into()));
            let outer_html = self.command(
                "DOM.getOuterHTML",
                Some(params),
                Some(attachment.session_id),
                deadline,
                None,
                clock,
            )?;
            observation.dom_text = Some(required_result_string(&outer_html, "outerHTML")?);
        }

        Ok(observation)
    }

    fn main_frame_url_with_clock<C: NavigationClock>(
        &mut self,
        context_key: &str,
        deadline_ms: u64,
        clock: &mut C,
    ) -> Result<String, NavigationDriveError> {
        let deadline = clock
            .now()
            .checked_add(Duration::from_millis(deadline_ms))
            .ok_or(NavigationDriveError::CdpFailure)?;
        self.ensure_attached(context_key, deadline, clock)?;
        let attachment = self
            .attachment
            .clone()
            .ok_or(NavigationDriveError::CdpFailure)?;
        let history = self.command(
            "Page.getNavigationHistory",
            None,
            Some(attachment.session_id),
            deadline,
            None,
            clock,
        )?;
        let current_index = history
            .get("currentIndex")
            .and_then(Value::as_u64)
            .and_then(|index| usize::try_from(index).ok())
            .ok_or(NavigationDriveError::CdpFailure)?;
        history
            .get("entries")
            .and_then(Value::as_array)
            .and_then(|entries| entries.get(current_index))
            .and_then(|entry| entry.get("url"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or(NavigationDriveError::CdpFailure)
    }

    fn navigate_with_clock<C: NavigationClock>(
        &mut self,
        context_key: &str,
        url: &str,
        wait: NavigationWait,
        deadline_ms: u64,
        tracker: &mut Tracker,
        clock: &mut C,
    ) -> Result<(), NavigationDriveError> {
        let deadline = clock
            .now()
            .checked_add(Duration::from_millis(deadline_ms))
            .ok_or(NavigationDriveError::CdpFailure)?;
        self.ensure_attached(context_key, deadline, clock)?;
        let attachment = self
            .attachment
            .clone()
            .ok_or(NavigationDriveError::CdpFailure)?;

        self.command(
            "Page.enable",
            None,
            Some(attachment.session_id.clone()),
            deadline,
            None,
            clock,
        )?;
        self.command(
            "Network.enable",
            None,
            Some(attachment.session_id.clone()),
            deadline,
            None,
            clock,
        )?;

        let mut params = Map::new();
        params.insert("url".into(), Value::String(url.to_string()));
        let navigate_result = self.command(
            "Page.navigate",
            Some(params),
            Some(attachment.session_id.clone()),
            deadline,
            Some((context_key, tracker)),
            clock,
        )?;
        if let Some(error_text) = navigate_result
            .get("errorText")
            .and_then(Value::as_str)
            .filter(|error_text| !error_text.is_empty())
        {
            return Err(NavigationDriveError::NavigationFailed {
                error_text: error_text.to_string(),
            });
        }

        if wait == NavigationWait::None {
            return Ok(());
        }

        self.settle_navigation(context_key, tracker, deadline, |_| false, clock)
    }

    /// Feed page events into `tracker` until it settles, `ended` reports the
    /// navigation over without settling, or `deadline` passes. Both
    /// `browser.navigate` and a click that navigated wait through here, so the
    /// two report `lifecycle`, `url_final` and settlement the same way.
    fn settle_navigation<C: NavigationClock>(
        &mut self,
        context_key: &str,
        tracker: &mut Tracker,
        deadline: Instant,
        ended: impl Fn(&Tracker) -> bool,
        clock: &mut C,
    ) -> Result<(), NavigationDriveError> {
        while clock.now() < deadline {
            self.read_turn(None, Some((context_key, tracker)), clock.now())?;
            if tracker.poll_settlement(clock.now()) || ended(tracker) {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(clock.now());
            clock.sleep(cmp::min(POLL_INTERVAL, remaining));
        }
        tracker.poll_settlement(clock.now());
        Ok(())
    }

    pub fn request_browser_close(&mut self) -> Result<(), NavigationDriveError> {
        // Teardown uses the same correlator as navigation so request ids remain
        // unique until the descriptor closes; a fixed close id could alias a
        // completed navigation response on a long-lived session.
        let command = self
            .transport
            .issue_command("Browser.close", None, None, Instant::now())
            .map_err(|_| NavigationDriveError::CdpFailure)?;
        let mut bytes = command
            .json_bytes()
            .map_err(|_| NavigationDriveError::CdpFailure)?;
        bytes.push(0);
        self.pipe
            .write_frame(&bytes)
            .map_err(|_| NavigationDriveError::ConnectorFailure)
    }

    fn ensure_attached<C: NavigationClock>(
        &mut self,
        context_key: &str,
        deadline: Instant,
        clock: &mut C,
    ) -> Result<(), NavigationDriveError> {
        if let Some(attachment) = &self.attachment {
            return if attachment.context_key == context_key {
                Ok(())
            } else {
                Err(NavigationDriveError::CdpFailure)
            };
        }

        // A dedicated target makes ownership explicit. Selecting an arbitrary
        // pre-existing tab would let one route drive a page whose custody was
        // never established for that route.
        //
        // `background: true` keeps the user's frontmost application in front.
        // Measured on macOS 27 with Chrome 153 (2026-09-23), sampling the
        // frontmost app every 100 ms: a browser launched with
        // `--no-startup-window` that then creates a foreground target (or is
        // handed a startup window, or launched via `open -g` / `open -g -j`)
        // takes focus within 0.4 s; creating the target with
        // `background: true` opens one on-screen window and focus never moves.
        // `newWindow: true` alongside it measured the same, so it is left out:
        // with no startup window Chrome must open a window for this target
        // anyway, and omitting it avoids a second window when one already
        // exists. `browser.present` is the deliberate way to front the page.
        let mut create_params = Map::new();
        create_params.insert("url".into(), Value::String("about:blank".into()));
        create_params.insert("background".into(), Value::Bool(true));
        let created = self.command(
            "Target.createTarget",
            Some(create_params),
            None,
            deadline,
            None,
            clock,
        )?;
        let target_id = required_result_string(&created, "targetId")?;

        let mut attach_params = Map::new();
        attach_params.insert("targetId".into(), Value::String(target_id.clone()));
        attach_params.insert("flatten".into(), Value::Bool(true));
        let attached = self.command(
            "Target.attachToTarget",
            Some(attach_params),
            None,
            deadline,
            None,
            clock,
        )?;
        let session_id = required_result_string(&attached, "sessionId")?;

        self.identities
            .attach(Attachment {
                target_id: target_id.clone(),
                session_id: session_id.clone(),
                frame_ids: Vec::new(),
                context_key: context_key.to_string(),
            })
            .map_err(|_| NavigationDriveError::CdpFailure)?;
        self.attachment = Some(AttachedTarget {
            target_id,
            session_id,
            context_key: context_key.to_string(),
        });
        Ok(())
    }

    fn command<C: NavigationClock>(
        &mut self,
        method: &str,
        params: Option<Map<String, Value>>,
        session_id: Option<String>,
        deadline: Instant,
        tracking: Option<(&str, &mut Tracker)>,
        clock: &mut C,
    ) -> Result<Map<String, Value>, NavigationDriveError> {
        let response =
            self.command_response(method, params, session_id, deadline, tracking, None, clock)?;
        if response.error.is_some() {
            return Err(NavigationDriveError::CdpFailure);
        }
        response.result.ok_or(NavigationDriveError::CdpFailure)
    }

    #[allow(clippy::too_many_arguments)]
    fn command_response<C: NavigationClock>(
        &mut self,
        method: &str,
        params: Option<Map<String, Value>>,
        session_id: Option<String>,
        deadline: Instant,
        tracking: Option<(&str, &mut Tracker)>,
        dispatched: Option<&mut dyn FnMut()>,
        clock: &mut C,
    ) -> Result<CdpResponse, NavigationDriveError> {
        self.command_response_inner(
            method, params, session_id, deadline, tracking, dispatched, None, clock,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn command_response_handling_javascript_dialogs<C: NavigationClock>(
        &mut self,
        method: &str,
        params: Option<Map<String, Value>>,
        session_id: Option<String>,
        deadline: Instant,
        dispatched: Option<&mut dyn FnMut()>,
        dialogs: &mut Vec<BrowserJavaScriptDialog>,
        tracking: (&str, &mut Tracker),
        clock: &mut C,
    ) -> Result<CdpResponse, NavigationDriveError> {
        self.command_response_inner(
            method,
            params,
            session_id,
            deadline,
            Some(tracking),
            dispatched,
            Some(dialogs),
            clock,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn command_response_inner<C: NavigationClock>(
        &mut self,
        method: &str,
        params: Option<Map<String, Value>>,
        session_id: Option<String>,
        deadline: Instant,
        mut tracking: Option<(&str, &mut Tracker)>,
        mut dispatched: Option<&mut dyn FnMut()>,
        mut handled_dialogs: Option<&mut Vec<BrowserJavaScriptDialog>>,
        clock: &mut C,
    ) -> Result<CdpResponse, NavigationDriveError> {
        if let Some(dialogs) = handled_dialogs.as_deref_mut() {
            self.dismiss_pending_javascript_dialogs(deadline, dialogs, &mut tracking, clock)?;
        }

        let command = self
            .transport
            .issue_command(method, params, session_id, clock.now())
            .map_err(|_| NavigationDriveError::CdpFailure)?;
        let command_id = command.id;
        let mut bytes = command
            .json_bytes()
            .map_err(|_| NavigationDriveError::CdpFailure)?;
        bytes.push(0);
        self.pipe
            .write_frame(&bytes)
            .map_err(|_| NavigationDriveError::ConnectorFailure)?;
        if let Some(callback) = dispatched.as_mut() {
            callback();
        }

        loop {
            if let Some(response) = self.pending_responses.remove(&command_id) {
                return Ok(response);
            }
            if clock.now() >= deadline {
                return Err(NavigationDriveError::CdpFailure);
            }
            let response = match tracking.as_mut() {
                Some((context_key, tracker)) => self.read_turn(
                    Some(command_id),
                    Some((*context_key, *tracker)),
                    clock.now(),
                )?,
                None => self.read_turn(Some(command_id), None, clock.now())?,
            };
            if let Some(dialogs) = handled_dialogs.as_deref_mut() {
                self.dismiss_pending_javascript_dialogs(deadline, dialogs, &mut tracking, clock)?;
            }
            if let Some(response) = response {
                return Ok(response);
            }
            let remaining = deadline.saturating_duration_since(clock.now());
            clock.sleep(cmp::min(POLL_INTERVAL, remaining));
        }
    }

    fn dismiss_pending_javascript_dialogs<C: NavigationClock>(
        &mut self,
        deadline: Instant,
        handled: &mut Vec<BrowserJavaScriptDialog>,
        tracking: &mut Option<(&str, &mut Tracker)>,
        clock: &mut C,
    ) -> Result<(), NavigationDriveError> {
        while let Some(dialog) = self.pending_javascript_dialogs.pop_front() {
            let mut params = Map::new();
            params.insert("accept".into(), Value::Bool(false));
            // Page events that arrive while the dialog is answered still
            // belong to the click, so they keep feeding its tracker.
            let response = self.command_response(
                "Page.handleJavaScriptDialog",
                Some(params),
                Some(dialog.session_id),
                deadline,
                tracking
                    .as_mut()
                    .map(|(context_key, tracker)| (*context_key, &mut **tracker)),
                None,
                clock,
            )?;
            if response.error.is_some() {
                return Err(NavigationDriveError::CdpFailure);
            }
            handled.push(BrowserJavaScriptDialog {
                dialog_type: dialog.dialog_type,
                response: JavaScriptDialogResponse::Dismissed,
            });
        }
        Ok(())
    }

    fn read_turn(
        &mut self,
        expected_response_id: Option<u64>,
        mut tracking: Option<(&str, &mut Tracker)>,
        observed_at: Instant,
    ) -> Result<Option<CdpResponse>, NavigationDriveError> {
        let bytes = match self.pipe.read(&mut self.read_buffer) {
            Ok(PipeRead::Bytes(bytes)) if bytes <= self.read_buffer.len() => bytes,
            Ok(PipeRead::Bytes(_)) | Ok(PipeRead::Closed) => {
                return Err(NavigationDriveError::ConnectorFailure)
            }
            Ok(PipeRead::WouldBlock) => return Ok(None),
            Err(_) => return Err(NavigationDriveError::ConnectorFailure),
        };

        let mut matched = None;
        for frame in self.decoder.push(&self.read_buffer[..bytes]) {
            let value: Value =
                serde_json::from_slice(&frame).map_err(|_| NavigationDriveError::CdpFailure)?;
            if value.get("id").is_some() {
                let response = self
                    .transport
                    .take_response(&frame)
                    .map_err(|_| NavigationDriveError::CdpFailure)?;
                if Some(response.id) == expected_response_id {
                    matched = Some(response);
                } else {
                    self.pending_responses.insert(response.id, response);
                }
                continue;
            }

            let event = self
                .transport
                .accept_event(&frame)
                .map_err(|_| NavigationDriveError::CdpFailure)?;
            let _ = self.transport.pop_event();
            if event.method == "Page.javascriptDialogOpening" {
                if let (Some(attachment), Some(session_id)) =
                    (self.attachment.as_ref(), event.session_id.as_deref())
                {
                    if session_id == attachment.session_id {
                        let dialog_type = event
                            .params
                            .as_ref()
                            .and_then(|params| params.get("type"))
                            .and_then(Value::as_str)
                            .filter(|value| !value.is_empty())
                            .unwrap_or("unknown")
                            .to_string();
                        self.pending_javascript_dialogs
                            .push_back(PendingJavaScriptDialog {
                                session_id: session_id.to_string(),
                                dialog_type,
                            });
                    }
                }
            }
            if let Some((context_key, tracker)) = tracking.as_mut() {
                self.apply_event(context_key, tracker, &event, observed_at);
            }
        }
        Ok(matched)
    }

    fn apply_event(
        &self,
        context_key: &str,
        tracker: &mut Tracker,
        event: &CdpEvent,
        observed_at: Instant,
    ) {
        let Some(attachment) = self.attachment.as_ref() else {
            return;
        };
        let Some(session_id) = event.session_id.as_deref() else {
            return;
        };
        let event_target = event
            .raw
            .get("targetId")
            .and_then(Value::as_str)
            .or_else(|| {
                event
                    .params
                    .as_ref()
                    .and_then(|params| params.get("targetId"))
                    .and_then(Value::as_str)
            })
            .unwrap_or(&attachment.target_id);
        if self
            .identities
            .context_for(event_target, session_id, None)
            .ok()
            != Some(context_key)
        {
            return;
        }

        match event.method.as_str() {
            "Page.loadEventFired" => tracker.load(observed_at),
            "Network.requestWillBeSent" => {
                // A redirect re-emits this event for the SAME request, carrying
                // the response that caused the redirect. The original request
                // never gets its own `loadingFinished`, so counting the
                // continuation as a new request leaks one in-flight forever and
                // the navigation can never reach network quiet.
                //
                // Measured against Chrome 151: `http://example.com` redirects to
                // https and never settled, while `https://example.com/` settled
                // immediately. On today's web nearly every bare-domain URL
                // redirects, so this made `wait: "settle"` unusable for real
                // navigation while looking correct on a page that happens not to
                // redirect.
                let is_redirect_continuation = event
                    .params
                    .as_ref()
                    .and_then(|params| params.get("redirectResponse"))
                    .is_some();
                if !is_redirect_continuation {
                    tracker.request_started();
                }
                if let Some(params) = event
                    .params
                    .as_ref()
                    .filter(|params| params.get("type").and_then(Value::as_str) == Some("Document"))
                {
                    if let (Some(request_id), Some(frame_id)) = (
                        params.get("requestId").and_then(Value::as_str),
                        params.get("frameId").and_then(Value::as_str),
                    ) {
                        tracker.document_request_started(request_id, frame_id);
                    }
                }
            }
            "Network.loadingFinished" => tracker.request_finished(observed_at),
            "Network.loadingFailed" => {
                tracker.request_finished(observed_at);
                if let Some(params) = event.params.as_ref() {
                    if let (Some(request_id), Some(error_text)) = (
                        params.get("requestId").and_then(Value::as_str),
                        params.get("errorText").and_then(Value::as_str),
                    ) {
                        tracker.document_request_failed(request_id, error_text.to_string());
                    }
                }
            }
            // These three carry only a frame id. A page target's main frame
            // id is its target id: measured against Chrome 153 (2026-09-25),
            // `Page.getFrameTree` returned the target id as the root frame id,
            // and every event for the main frame carried it while an iframe's
            // carried its own. So an event naming any other frame is a
            // subframe's and never counts as the page navigating.
            "Page.frameRequestedNavigation" | "Page.frameStartedNavigating" => {
                let Some(params) = event.params.as_ref() else {
                    return;
                };
                if params.get("frameId").and_then(Value::as_str)
                    != Some(attachment.target_id.as_str())
                {
                    return;
                }
                // A link that opens a new tab or starts a download still
                // requests a navigation from this frame, but this page stays
                // where it is.
                if params
                    .get("disposition")
                    .and_then(Value::as_str)
                    .is_some_and(|disposition| disposition != "currentTab")
                {
                    return;
                }
                // Same-document navigations are reported through
                // `Page.navigatedWithinDocument` instead.
                if params
                    .get("navigationType")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| kind.contains("SameDocument") || kind == "sameDocument")
                {
                    return;
                }
                tracker.main_frame_navigation_requested();
            }
            "Page.navigatedWithinDocument" => {
                let Some(params) = event.params.as_ref() else {
                    return;
                };
                if params.get("frameId").and_then(Value::as_str)
                    != Some(attachment.target_id.as_str())
                {
                    return;
                }
                if let Some(url) = params.get("url").and_then(Value::as_str) {
                    tracker.main_frame_navigated_within_document(url.to_string());
                }
            }
            "Page.frameStoppedLoading" => {
                if event
                    .params
                    .as_ref()
                    .and_then(|params| params.get("frameId"))
                    .and_then(Value::as_str)
                    == Some(attachment.target_id.as_str())
                {
                    tracker.main_frame_stopped_loading();
                }
            }
            "Page.frameNavigated" => {
                let frame = event
                    .params
                    .as_ref()
                    .and_then(|params| params.get("frame"))
                    .and_then(Value::as_object);
                if let Some(frame) = frame.filter(|frame| !frame.contains_key("parentId")) {
                    if let Some(url) = frame.get("url").and_then(Value::as_str) {
                        let frame_id = frame.get("id").and_then(Value::as_str).map(str::to_string);
                        // Chrome commits its own error page for a failed
                        // navigation and names what it could not load here.
                        match frame
                            .get("unreachableUrl")
                            .and_then(Value::as_str)
                            .filter(|unreachable| !unreachable.is_empty())
                        {
                            Some(unreachable) => tracker.main_frame_navigation_unreachable(
                                frame_id,
                                url.to_string(),
                                unreachable,
                            ),
                            None => tracker.main_frame_navigated(frame_id, url.to_string()),
                        }
                    }
                }
            }
            "Network.responseReceived" => {
                let Some(params) = event.params.as_ref() else {
                    return;
                };
                if params.get("type").and_then(Value::as_str) != Some("Document") {
                    return;
                }
                let Some(frame_id) = params.get("frameId").and_then(Value::as_str) else {
                    return;
                };
                let Some(response) = params.get("response").and_then(Value::as_object) else {
                    return;
                };
                let Some(status) = response
                    .get("status")
                    .and_then(Value::as_u64)
                    .and_then(|status| u16::try_from(status).ok())
                else {
                    return;
                };
                let Some(status_text) = response.get("statusText").and_then(Value::as_str) else {
                    return;
                };
                let Some(headers) = response.get("headers").and_then(Value::as_object) else {
                    return;
                };
                tracker.observe_main_frame_response(
                    frame_id,
                    status,
                    status_text.to_string(),
                    headers.clone(),
                );
            }
            _ => {}
        }
    }
}

fn parse_flattened_dom_nodes(
    result: &Map<String, Value>,
) -> Result<Vec<RawDomNode>, ClassificationUnavailable> {
    let values = result
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or(ClassificationUnavailable::FlattenedNodesMissing)?;
    let mut nodes = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let field_invalid = |field| ClassificationUnavailable::NodeFieldInvalid { index, field };
        let object = value
            .as_object()
            .ok_or(ClassificationUnavailable::NodeNotObject { index })?;
        if object
            .get("nodeType")
            .and_then(Value::as_u64)
            .ok_or(field_invalid("nodeType"))?
            != 1
        {
            continue;
        }
        let node_id = object
            .get("nodeId")
            .and_then(Value::as_u64)
            .filter(|id| *id > 0)
            .ok_or(field_invalid("nodeId"))?;
        let backend_node_id = object
            .get("backendNodeId")
            .and_then(Value::as_u64)
            .filter(|id| *id > 0)
            .ok_or(field_invalid("backendNodeId"))?;
        let local_name = object
            .get("localName")
            .and_then(Value::as_str)
            .or_else(|| object.get("nodeName").and_then(Value::as_str))
            .ok_or(field_invalid("localName"))?
            .to_ascii_lowercase();
        // DOM.getFlattenedDocument supplies the complete attribute array for
        // element nodes. Missing it makes security-relevant facts unavailable,
        // so the entire projection becomes an unknown classification.
        let attribute_values = object
            .get("attributes")
            .and_then(Value::as_array)
            .ok_or(ClassificationUnavailable::AttributesMissing { node_id })?;
        if attribute_values.len() % 2 != 0 {
            return Err(ClassificationUnavailable::AttributesOddLength {
                node_id,
                length: attribute_values.len(),
            });
        }
        let attribute_text = |position: usize| {
            attribute_values[position]
                .as_str()
                .ok_or(ClassificationUnavailable::AttributeNotString { node_id, position })
        };
        let mut attributes = HashMap::new();
        for pair in 0..attribute_values.len() / 2 {
            let name = attribute_text(pair * 2)?.to_ascii_lowercase();
            let value = attribute_text(pair * 2 + 1)?.to_string();
            if attributes.insert(name, value).is_some() {
                return Err(ClassificationUnavailable::DuplicateAttribute { node_id });
            }
        }
        let assigned_slot_backend_node_id = object
            .get("assignedSlot")
            .and_then(Value::as_object)
            .and_then(|slot| slot.get("backendNodeId"))
            .and_then(Value::as_u64)
            .filter(|id| *id > 0);
        nodes.push(RawDomNode {
            node_id,
            parent_id: object
                .get("parentId")
                .and_then(Value::as_u64)
                .filter(|id| *id > 0),
            backend_node_id,
            local_name,
            attributes,
            assigned_slot_backend_node_id,
        });
    }
    Ok(nodes)
}

/// The origin the classifier compares activation destinations against.
///
/// Callers hold the document's URL (`https://example.com/`), and the
/// classifier accepts only a bare origin (`https://example.com`). Passing the
/// URL through made every classification on a page with a path fail as an
/// invalid origin, which authorization then read as an unverified form.
fn document_origin(document_url: &str) -> Result<String, ClassificationUnavailable> {
    classification::canonical_origin_from_url(document_url)
        .or_else(|| classification::canonical_origin(document_url))
        .ok_or(ClassificationUnavailable::DocumentOriginUnavailable)
}

/// Classify one element of a document captured with
/// `DOM.getFlattenedDocument {depth: -1, pierce: true}`, exactly as the
/// snapshot path does. `document_url` is the page's URL as the browser
/// reports it; `result` is the command's `result` object.
///
/// Public so a host-browser probe can run the production classification over
/// a live capture without driving a whole browser session.
pub fn classify_flattened_document(
    result: &Map<String, Value>,
    target: &BackendNodeIdentity,
    document_epoch: u64,
    document_url: &str,
) -> Result<NonTypeClassificationRecord, ClassificationUnavailable> {
    let origin = document_origin(document_url)?;
    let nodes = parse_flattened_dom_nodes(result)?;
    build_non_type_classification(&nodes, target, document_epoch, &origin)
}

fn build_non_type_classification(
    nodes: &[RawDomNode],
    target_identity: &BackendNodeIdentity,
    document_epoch: u64,
    current_origin: &str,
) -> Result<NonTypeClassificationRecord, ClassificationUnavailable> {
    let mut by_node_id = HashMap::with_capacity(nodes.len());
    let mut by_backend_id = HashMap::with_capacity(nodes.len());
    for (index, node) in nodes.iter().enumerate() {
        if by_node_id.insert(node.node_id, index).is_some() {
            return Err(ClassificationUnavailable::DuplicateNodeId {
                node_id: node.node_id,
            });
        }
        if by_backend_id.insert(node.backend_node_id, index).is_some() {
            return Err(ClassificationUnavailable::DuplicateBackendNodeId {
                backend_node_id: node.backend_node_id,
            });
        }
    }
    let target_index = *by_backend_id.get(&target_identity.backend_node_id).ok_or(
        ClassificationUnavailable::TargetNotInDocument {
            backend_node_id: target_identity.backend_node_id,
        },
    )?;
    let context = DomClassificationContext {
        nodes,
        by_node_id: &by_node_id,
        by_backend_id: &by_backend_id,
        target_id: &target_identity.target_id,
        frame_id: &target_identity.frame_id,
        current_origin,
    };
    let target = context.element(target_index, true);
    let mut input = NonTypeClassificationInput::new(document_epoch, target, current_origin);
    let mut current = target_index;
    let mut visited = HashSet::from([current]);
    while let Some(parent) = context.composed_parent(current) {
        if !visited.insert(parent) {
            return Err(ClassificationUnavailable::ComposedParentCycle {
                node_id: nodes[parent].node_id,
            });
        }
        input.composed_ancestors.push(context.element(parent, true));
        current = parent;
    }
    classification::classify_click(&input).map_err(ClassificationUnavailable::ClassifierRejected)
}

struct DomClassificationContext<'a> {
    nodes: &'a [RawDomNode],
    by_node_id: &'a HashMap<u64, usize>,
    by_backend_id: &'a HashMap<u64, usize>,
    target_id: &'a str,
    frame_id: &'a str,
    current_origin: &'a str,
}

impl DomClassificationContext<'_> {
    fn identity(&self, index: usize) -> NodeIdentityInput {
        NodeIdentityInput::new(
            self.target_id,
            self.frame_id,
            self.nodes[index].backend_node_id,
        )
    }

    fn composed_parent(&self, index: usize) -> Option<usize> {
        let node = self.nodes.get(index)?;
        node.assigned_slot_backend_node_id
            .and_then(|backend| self.by_backend_id.get(&backend).copied())
            .or_else(|| {
                node.parent_id
                    .and_then(|parent| self.by_node_id.get(&parent).copied())
            })
    }

    fn dom_parent(&self, index: usize) -> Option<usize> {
        self.nodes
            .get(index)?
            .parent_id
            .and_then(|parent| self.by_node_id.get(&parent).copied())
    }

    fn form_owner(&self, index: usize) -> Option<usize> {
        if let Some(form_id) = self.nodes[index].attributes.get("form") {
            return self.nodes.iter().position(|node| {
                node.local_name == "form"
                    && node.attributes.get("id").is_some_and(|id| id == form_id)
            });
        }
        let mut current = self.dom_parent(index);
        let mut visited = HashSet::new();
        while let Some(parent) = current {
            if !visited.insert(parent) {
                return None;
            }
            if self.nodes[parent].local_name == "form" {
                return Some(parent);
            }
            current = self.dom_parent(parent);
        }
        None
    }

    fn label_control(&self, label_index: usize) -> Option<usize> {
        if let Some(control_id) = self.nodes[label_index].attributes.get("for") {
            return self.nodes.iter().position(|node| {
                is_labelable(&node.local_name)
                    && node.attributes.get("id").is_some_and(|id| id == control_id)
            });
        }
        self.nodes.iter().enumerate().find_map(|(index, node)| {
            (is_labelable(&node.local_name) && self.is_dom_descendant(index, label_index))
                .then_some(index)
        })
    }

    fn is_dom_descendant(&self, candidate: usize, ancestor: usize) -> bool {
        let mut current = self.dom_parent(candidate);
        let mut visited = HashSet::new();
        while let Some(parent) = current {
            if parent == ancestor {
                return true;
            }
            if !visited.insert(parent) {
                return false;
            }
            current = self.dom_parent(parent);
        }
        false
    }

    /// Every index reaching here came from `by_node_id` / `by_backend_id`,
    /// which were built from `nodes` itself, so indexing cannot miss.
    fn element(&self, index: usize, include_label_control: bool) -> ElementClassificationInput {
        let node = &self.nodes[index];
        let kind = target_kind(&node.local_name);
        let mut element = ElementClassificationInput::new(self.identity(index), kind)
            .disabled(node.attributes.contains_key("disabled"));
        if matches!(kind, TargetKind::Input | TargetKind::Button) {
            if let Some(input_type) = node.attributes.get("type") {
                element = element.input_type(input_type.to_ascii_lowercase());
            }
        }
        let tokens = autocomplete_tokens(node.attributes.get("autocomplete"));
        if !tokens.is_empty() {
            element = element.autocomplete(tokens);
        }
        if node.local_name == "input"
            && node
                .attributes
                .get("type")
                .is_some_and(|input_type| input_type.eq_ignore_ascii_case("password"))
        {
            element = element.password(true);
        }
        if let Some(owner) = self.form_owner(index) {
            element = element.form_owner(self.identity(owner));
            for (control_index, control) in self.nodes.iter().enumerate() {
                if !is_form_control(&control.local_name)
                    || self.form_owner(control_index) != Some(owner)
                {
                    continue;
                }
                let mut associated = AssociatedFormControlInput::new(self.identity(control_index));
                let tokens = autocomplete_tokens(control.attributes.get("autocomplete"));
                if !tokens.is_empty() {
                    associated = associated.with_tokens(tokens);
                }
                let password = control.local_name == "input"
                    && control
                        .attributes
                        .get("type")
                        .is_some_and(|input_type| input_type.eq_ignore_ascii_case("password"));
                element = element.associated_control(associated.with_password(password));
            }
        }
        if let Some(destination) = self.activation_destination(index) {
            element = element.destination(destination);
        }
        if node.local_name == "label" && include_label_control {
            if let Some(control) = self.label_control(index) {
                element = element.label_for(self.element(control, false));
            } else {
                element.is_label = true;
            }
        }
        element
    }

    fn activation_destination(&self, index: usize) -> Option<String> {
        let node = &self.nodes[index];
        let declared = match node.local_name.as_str() {
            "a" | "area" => node.attributes.get("href"),
            "button" | "input" => node.attributes.get("formaction").or_else(|| {
                self.form_owner(index)
                    .and_then(|owner| self.nodes[owner].attributes.get("action"))
            }),
            _ => None,
        }?;
        if declared.contains("://") {
            return Some(declared.clone());
        }
        if declared.starts_with('/') {
            return classification::canonical_origin(self.current_origin)
                .map(|origin| format!("{origin}{declared}"));
        }
        None
    }
}

fn target_kind(local_name: &str) -> TargetKind {
    match local_name {
        "button" => TargetKind::Button,
        "input" => TargetKind::Input,
        "a" => TargetKind::Anchor,
        "area" => TargetKind::Area,
        _ => TargetKind::Other,
    }
}

fn is_labelable(local_name: &str) -> bool {
    matches!(local_name, "button" | "input" | "select" | "textarea")
}

fn is_form_control(local_name: &str) -> bool {
    matches!(
        local_name,
        "button" | "input" | "select" | "textarea" | "output"
    )
}

fn autocomplete_tokens(value: Option<&String>) -> Vec<String> {
    value
        .into_iter()
        .flat_map(|value| value.split_ascii_whitespace())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn hit_test_coordinate(value: f64) -> Result<i64, ClickDriveError> {
    let rounded = value.round();
    if !(0.0..=f64::from(i32::MAX)).contains(&rounded) {
        return Err(ClickDriveError::NoPosition);
    }
    Ok(rounded as i64)
}

fn mouse_event_params(event_type: &str, position: BrowserClickPosition) -> Map<String, Value> {
    let mut params = Map::new();
    params.insert("type".into(), Value::String(event_type.to_string()));
    params.insert(
        "x".into(),
        Value::Number(
            serde_json::Number::from_f64(position.x_css)
                .expect("eligible click x-coordinate is finite"),
        ),
    );
    params.insert(
        "y".into(),
        Value::Number(
            serde_json::Number::from_f64(position.y_css)
                .expect("eligible click y-coordinate is finite"),
        ),
    );
    params
}

fn required_content_quads(result: &Map<String, Value>) -> Result<Vec<Quad>, NavigationDriveError> {
    let values = result
        .get("quads")
        .and_then(Value::as_array)
        .filter(|values| values.len() <= 4_096)
        .ok_or(NavigationDriveError::CdpFailure)?;
    values
        .iter()
        .map(|value| {
            let coordinates = value
                .as_array()
                .filter(|coordinates| coordinates.len() == 8)
                .ok_or(NavigationDriveError::CdpFailure)?;
            let mut points = [(0.0, 0.0); 4];
            for (index, point) in points.iter_mut().enumerate() {
                point.0 = coordinates[index * 2]
                    .as_f64()
                    .ok_or(NavigationDriveError::CdpFailure)?;
                point.1 = coordinates[index * 2 + 1]
                    .as_f64()
                    .ok_or(NavigationDriveError::CdpFailure)?;
            }
            Ok(Quad::new(points))
        })
        .collect()
}

fn described_node_contains(
    result: &Map<String, Value>,
    backend_node_id: u64,
) -> Result<bool, NavigationDriveError> {
    let root = result
        .get("node")
        .and_then(Value::as_object)
        .ok_or(NavigationDriveError::CdpFailure)?;
    let mut pending = vec![root];
    let mut visited = 0usize;
    while let Some(node) = pending.pop() {
        visited = visited.saturating_add(1);
        if visited > 4_096 {
            return Err(NavigationDriveError::CdpFailure);
        }
        if node.get("backendNodeId").and_then(Value::as_u64) == Some(backend_node_id) {
            return Ok(true);
        }
        if let Some(children) = node.get("children") {
            let children = children
                .as_array()
                .ok_or(NavigationDriveError::CdpFailure)?;
            for child in children {
                pending.push(child.as_object().ok_or(NavigationDriveError::CdpFailure)?);
            }
        }
    }
    Ok(false)
}

fn required_ax_node(
    result: &Map<String, Value>,
    field: &str,
) -> Result<RawAxNode, NavigationDriveError> {
    result
        .get(field)
        .ok_or(NavigationDriveError::CdpFailure)
        .and_then(RawAxNode::from_value)
}

fn required_ax_nodes(result: &Map<String, Value>) -> Result<Vec<RawAxNode>, NavigationDriveError> {
    result
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or(NavigationDriveError::CdpFailure)?
        .iter()
        .map(RawAxNode::from_value)
        .collect()
}

impl RawAxNode {
    fn from_value(value: &Value) -> Result<Self, NavigationDriveError> {
        let object = value.as_object().ok_or(NavigationDriveError::CdpFailure)?;
        let node_id = object
            .get("nodeId")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 4_096)
            .ok_or(NavigationDriveError::CdpFailure)?
            .to_string();
        let ignored = object
            .get("ignored")
            .and_then(Value::as_bool)
            .ok_or(NavigationDriveError::CdpFailure)?;
        let child_ids = match object.get("childIds") {
            None => Vec::new(),
            Some(Value::Array(values)) => values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .filter(|value| !value.is_empty() && value.len() <= 4_096)
                        .map(str::to_string)
                        .ok_or(NavigationDriveError::CdpFailure)
                })
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => return Err(NavigationDriveError::CdpFailure),
        };
        let backend_node_id = match object.get("backendDOMNodeId") {
            None => None,
            Some(value) => Some(
                value
                    .as_u64()
                    .filter(|value| *value > 0)
                    .ok_or(NavigationDriveError::CdpFailure)?,
            ),
        };
        let frame_id = match object.get("frameId") {
            None => None,
            Some(value) => Some(
                value
                    .as_str()
                    .filter(|value| !value.is_empty() && value.len() <= 4_096)
                    .ok_or(NavigationDriveError::CdpFailure)?
                    .to_string(),
            ),
        };
        Ok(Self {
            node_id,
            ignored,
            role: ax_value_text(object.get("role")).unwrap_or_default(),
            name: ax_value_text(object.get("name")).unwrap_or_default(),
            value: ax_value_text(object.get("value")),
            child_ids,
            backend_node_id,
            frame_id,
        })
    }
}

fn ax_value_text(value: Option<&Value>) -> Option<String> {
    let value = value?.as_object()?.get("value")?;
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn bounded_ax_field(value: &str, max_bytes: usize) -> (String, bool) {
    let bounded = truncate_ax_field(value, max_bytes);
    let truncated = bounded.len() != value.len();
    (bounded, truncated)
}

fn traverse_ax_tree<F>(
    root: RawAxNode,
    target_id: &str,
    max_nodes: usize,
    max_depth: usize,
    mut fetch_children: F,
) -> Result<BrowserSnapshotObservation, NavigationDriveError>
where
    F: FnMut(&str, Option<&str>) -> Result<Vec<RawAxNode>, NavigationDriveError>,
{
    if max_nodes == 0 || target_id.is_empty() {
        return Err(NavigationDriveError::CdpFailure);
    }
    let root_id = root.node_id.clone();
    let mut scheduled = HashSet::from([root_id.clone()]);
    let mut stack = vec![PendingAxNode {
        node: Some(root),
        node_id: root_id,
        depth: 0,
        frame_path: Vec::new(),
        ancestors: HashSet::new(),
    }];
    let mut records = Vec::new();
    let mut refs = Vec::new();
    let mut fallback_counts: HashMap<(Vec<String>, String, String), u64> = HashMap::new();
    let mut node_cache = HashMap::<String, RawAxNode>::new();
    let mut processed = 0usize;
    let mut ax_truncated = false;
    let mut refs_truncated = false;

    while let Some(pending) = stack.pop() {
        if processed == max_nodes {
            ax_truncated = true;
            refs_truncated = true;
            break;
        }
        let node = pending.node.ok_or(NavigationDriveError::CdpFailure)?;
        if node.node_id != pending.node_id {
            return Err(NavigationDriveError::CdpFailure);
        }
        processed += 1;

        let mut frame_path = pending.frame_path;
        if let Some(frame_id) = &node.frame_id {
            if frame_path.last() != Some(frame_id) {
                frame_path.push(frame_id.clone());
            }
        }
        let (role, role_truncated) = bounded_ax_field(&node.role, MAX_ROLE_BYTES);
        let (name, name_truncated) = bounded_ax_field(&node.name, MAX_NAME_BYTES);
        let (value, value_truncated) = match node.value.as_deref() {
            Some(value) => {
                let (value, truncated) = bounded_ax_field(value, MAX_VALUE_BYTES);
                (Some(value), truncated)
            }
            None => (None, false),
        };
        if role_truncated || name_truncated || value_truncated {
            ax_truncated = true;
            refs_truncated = true;
        }

        let mut reference = None;
        if !node.ignored {
            if let (Some(backend_node_id), Some(frame_id)) =
                (node.backend_node_id, frame_path.last())
            {
                if refs.len() == MAX_REFS {
                    refs_truncated = true;
                } else {
                    let key = (frame_path.clone(), role.clone(), name.clone());
                    let nth = fallback_counts.entry(key).or_insert(0);
                    let ref_name = format!("e{}", refs.len() + 1);
                    let captured = SnapshotRef::new(&ref_name, &role, &name, *nth)
                        .map_err(|_| NavigationDriveError::CdpFailure)?;
                    let backend_identity =
                        BackendNodeIdentity::new(target_id, frame_id, backend_node_id)
                            .map_err(|_| NavigationDriveError::CdpFailure)?;
                    refs.push(RefRecord {
                        captured,
                        frame_path: frame_path.clone(),
                        backend_identity: Some(backend_identity),
                        raw_role: Some(role.clone()),
                        raw_name: Some(name.clone()),
                        classification: Err(ClassificationUnavailable::NotCaptured),
                    });
                    *nth = nth.saturating_add(1);
                    reference = Some(ref_name);
                }
            }
            records.push(AxRecord {
                depth: pending.depth as i64,
                role,
                name,
                value,
                reference,
            });
        }

        let mut ancestors = pending.ancestors;
        ancestors.insert(node.node_id.clone());
        let node_child_ids = node.child_ids;
        let mut child_ids = Vec::new();
        for child_id in node_child_ids {
            // A back-edge names an element already represented on this path. Cutting
            // it avoids infinite recursion without hiding any accessibility node.
            if ancestors.contains(&child_id) {
                continue;
            }
            // A repeated node identity elsewhere in the graph is already represented,
            // so omitting its duplicate edge is lossless for the flattened snapshot.
            if !scheduled.insert(child_id.clone()) {
                continue;
            }
            child_ids.push(child_id);
        }
        if child_ids.is_empty() {
            continue;
        }
        if pending.depth >= max_depth {
            ax_truncated = true;
            refs_truncated = true;
            continue;
        }

        let available = max_nodes.saturating_sub(processed.saturating_add(stack.len()));
        if child_ids.len() > available {
            ax_truncated = true;
            refs_truncated = true;
            child_ids.truncate(available);
        }
        if child_ids.is_empty() {
            continue;
        }
        if child_ids
            .iter()
            .any(|child_id| !node_cache.contains_key(child_id))
        {
            // Chromium can return the descendants it traversed while resolving an
            // ignored child. Caching that bounded response avoids sending one command
            // per intermediate node and still follows only declared child identities.
            let selected_ids = child_ids.iter().cloned().collect::<HashSet<_>>();
            // Cached descendants are an optimization only. Keeping the immediate
            // children first ensures cache pressure can never make a declared edge
            // disappear or turn a complete traversal into a protocol failure.
            node_cache.retain(|node_id, _| selected_ids.contains(node_id));
            let fetched = fetch_children(&node.node_id, frame_path.last().map(String::as_str))?;
            let mut ordered = fetched
                .iter()
                .filter(|child| selected_ids.contains(&child.node_id))
                .cloned()
                .collect::<Vec<_>>();
            ordered.extend(
                fetched
                    .into_iter()
                    .filter(|child| !selected_ids.contains(&child.node_id)),
            );
            for child in ordered {
                if node_cache.len() == max_nodes && !selected_ids.contains(&child.node_id) {
                    // Descendants omitted only from this command-local cache can be
                    // fetched when their parent is visited, so this is not a lossy
                    // traversal cut and does not change completeness flags.
                    continue;
                }
                match node_cache.entry(child.node_id.clone()) {
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(child);
                    }
                    std::collections::hash_map::Entry::Occupied(entry) if entry.get() == &child => {
                    }
                    std::collections::hash_map::Entry::Occupied(_) => {
                        return Err(NavigationDriveError::CdpFailure)
                    }
                }
            }
        }
        let mut selected = child_ids
            .into_iter()
            .map(|child_id| {
                node_cache
                    .remove(&child_id)
                    .map(|child| (child_id, child))
                    .ok_or(NavigationDriveError::CdpFailure)
            })
            .collect::<Result<Vec<_>, _>>()?;
        selected.reverse();
        for (child_id, child) in selected {
            stack.push(PendingAxNode {
                node: Some(child),
                node_id: child_id,
                depth: pending.depth + 1,
                frame_path: frame_path.clone(),
                ancestors: ancestors.clone(),
            });
        }
    }

    Ok(BrowserSnapshotObservation {
        records,
        dom_text: None,
        refs,
        ax_truncated,
        refs_truncated,
    })
}

fn cdp_error_text(error: Map<String, Value>) -> String {
    error
        .get("message")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| Value::Object(error).to_string())
}

fn required_result_string(
    result: &Map<String, Value>,
    field: &str,
) -> Result<String, NavigationDriveError> {
    result
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or(NavigationDriveError::CdpFailure)
}

fn required_result_number(
    result: &Map<String, Value>,
    field: &str,
) -> Result<f64, NavigationDriveError> {
    result
        .get(field)
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
        .ok_or(NavigationDriveError::CdpFailure)
}

fn optional_result_number(
    result: &Map<String, Value>,
    field: &str,
) -> Result<Option<f64>, NavigationDriveError> {
    match result.get(field) {
        None => Ok(None),
        Some(value) => value
            .as_f64()
            .filter(|number| number.is_finite())
            .map(Some)
            .ok_or(NavigationDriveError::CdpFailure),
    }
}

fn json_finite_number(value: f64) -> Result<Value, NavigationDriveError> {
    serde_json::Number::from_f64(value)
        .map(Value::Number)
        .ok_or(NavigationDriveError::CdpFailure)
}

pub(crate) trait NavigationClock {
    fn now(&mut self) -> Instant;
    fn sleep(&mut self, duration: Duration);
}

struct SystemNavigationClock;

impl NavigationClock for SystemNavigationClock {
    fn now(&mut self) -> Instant {
        Instant::now()
    }

    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;

    use serde_json::json;

    use super::*;
    use crate::browser::QUIET_MS;
    use crate::snapshot_store::{
        new_snapshot_id, BrowserSnapshotStore, RefCandidate, RefResolution, TextSnapshot, AX_SCHEMA,
    };

    #[derive(Default)]
    struct FakePipe {
        writes: Vec<Value>,
        reads: VecDeque<Vec<u8>>,
    }

    impl FakePipe {
        fn with_frames(frames: impl IntoIterator<Item = Value>) -> Self {
            let reads = frames
                .into_iter()
                .map(|frame| {
                    let mut bytes = serde_json::to_vec(&frame).unwrap();
                    bytes.push(0);
                    bytes
                })
                .collect();
            Self {
                writes: Vec::new(),
                reads,
            }
        }
    }

    impl CdpPipeIo for FakePipe {
        fn write_frame(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.writes
                .push(serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap());
            Ok(())
        }

        fn read(&mut self, destination: &mut [u8]) -> io::Result<PipeRead> {
            let Some(bytes) = self.reads.pop_front() else {
                return Ok(PipeRead::WouldBlock);
            };
            destination[..bytes.len()].copy_from_slice(&bytes);
            Ok(PipeRead::Bytes(bytes.len()))
        }
    }

    struct FakeClock {
        now: Instant,
    }

    impl FakeClock {
        fn new() -> Self {
            Self {
                now: Instant::now(),
            }
        }
    }

    impl NavigationClock for FakeClock {
        fn now(&mut self) -> Instant {
            self.now
        }

        fn sleep(&mut self, duration: Duration) {
            self.now += duration;
        }
    }

    fn driver(frames: impl IntoIterator<Item = Value>) -> CdpNavigationDriver<FakePipe> {
        CdpNavigationDriver::new(
            FakePipe::with_frames(frames),
            CdpTransport::new(),
            CdpFrameDecoder::default(),
        )
    }

    fn attached_driver(frames: impl IntoIterator<Item = Value>) -> CdpNavigationDriver<FakePipe> {
        let mut driver = driver(frames);
        driver
            .identities
            .attach(Attachment {
                target_id: "target-own".into(),
                session_id: "session-own".into(),
                frame_ids: Vec::new(),
                context_key: "route-own".into(),
            })
            .unwrap();
        driver.attachment = Some(AttachedTarget {
            target_id: "target-own".into(),
            session_id: "session-own".into(),
            context_key: "route-own".into(),
        });
        driver
    }

    fn event(method: &str, params: Value) -> CdpEvent {
        let raw = json!({
            "method": method,
            "sessionId": "session-own",
            "params": params,
        });
        CdpEvent {
            method: method.into(),
            params: raw["params"].as_object().cloned(),
            session_id: Some("session-own".into()),
            raw,
        }
    }

    fn ax_node(
        node_id: &str,
        role: &str,
        name: &str,
        child_ids: &[&str],
        backend_node_id: u64,
        frame_id: Option<&str>,
    ) -> Value {
        let mut node = json!({
            "nodeId": node_id,
            "ignored": false,
            "role": {"type": "role", "value": role},
            "name": {"type": "computedString", "value": name},
            "childIds": child_ids,
            "backendDOMNodeId": backend_node_id,
        });
        if let Some(frame_id) = frame_id {
            node["frameId"] = Value::String(frame_id.to_string());
        }
        node
    }

    fn raw_node(
        node_id: &str,
        role: &str,
        name: &str,
        child_ids: &[&str],
        backend_node_id: u64,
        frame_id: Option<&str>,
    ) -> RawAxNode {
        RawAxNode::from_value(&ax_node(
            node_id,
            role,
            name,
            child_ids,
            backend_node_id,
            frame_id,
        ))
        .unwrap()
    }

    fn flattened_dom_node(
        node_id: u64,
        parent_id: Option<u64>,
        backend_node_id: u64,
        local_name: &str,
        attributes: &[&str],
    ) -> Value {
        let mut node = json!({
            "nodeId": node_id,
            "nodeType": 1,
            "backendNodeId": backend_node_id,
            "nodeName": local_name.to_ascii_uppercase(),
            "localName": local_name,
            "attributes": attributes,
        });
        if let Some(parent_id) = parent_id {
            node["parentId"] = json!(parent_id);
        }
        node
    }

    fn layout_metrics(x: f64, y: f64, width: f64, height: f64) -> Value {
        json!({
            "cssVisualViewport": {
                "offsetX": x,
                "offsetY": y,
                "clientWidth": width,
                "clientHeight": height,
                "scale": 1.0
            },
            "visualViewport": {
                "offsetX": x * 2.0,
                "offsetY": y * 2.0,
                "clientWidth": width * 2.0,
                "clientHeight": height * 2.0,
                "scale": 1.0
            }
        })
    }

    #[test]
    fn screenshot_reads_device_and_visual_scales_from_cdp_responses() {
        const ONE_BY_ONE_PNG_B64: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==";
        let css_viewport = json!({
            "offsetX": 10.5,
            "offsetY": 20.25,
            "clientWidth": 320.0,
            "clientHeight": 180.0,
            "scale": 1.75
        });
        // The deprecated sibling, carrying DEVICE pixels as a real browser does
        // on a scaled display. Present and different on purpose: reading it
        // instead yields numbers that look like a plausible viewport, so a
        // fixture offering only one field cannot tell the two apart -- and the
        // wrong one produces a pixel-to-css mapping that is the identity, which
        // is exactly what a caller cannot see.
        let device_viewport = json!({
            "offsetX": 21.0,
            "offsetY": 40.5,
            "clientWidth": 640.0,
            "clientHeight": 360.0,
            "scale": 1.75
        });
        let metrics = json!({
            "cssVisualViewport": css_viewport,
            "visualViewport": device_viewport,
        });
        let frames = [
            json!({"id":1,"sessionId":"session-own","result":metrics.clone()}),
            json!({"id":2,"sessionId":"session-own","result":{"result":{"type":"number","value":2.25}}}),
            json!({"id":3,"sessionId":"session-own","result":{"data":ONE_BY_ONE_PNG_B64}}),
            json!({"id":4,"sessionId":"session-own","result":metrics}),
            json!({"id":5,"sessionId":"session-own","result":{"result":{"type":"number","value":2.25}}}),
        ];
        let mut driver = attached_driver(frames);
        let mut clock = FakeClock::new();

        let screenshot = driver
            .screenshot_for_test("route-own", 7, 100, false, &mut clock)
            .expect("the CDP responses describe a coherent screenshot");

        assert_eq!(screenshot.image_png_b64, ONE_BY_ONE_PNG_B64);
        assert_eq!(screenshot.before, screenshot.after);
        assert_eq!(screenshot.before.document_epoch, 7);
        assert_eq!(screenshot.before.transform.x_input_css, 10.5);
        assert_eq!(screenshot.before.transform.y_input_css, 20.25);
        assert_eq!(screenshot.before.transform.width_input_css, 320.0);
        assert_eq!(screenshot.before.transform.height_input_css, 180.0);
        assert_eq!(screenshot.before.transform.device_scale_factor, 2.25);
        assert_eq!(screenshot.before.transform.visual_viewport_scale, 1.75);
        assert!(!screenshot.invalidation_observed);

        let methods: Vec<_> = driver
            .pipe
            .writes
            .iter()
            .map(|write| &write["method"])
            .collect();
        assert_eq!(
            methods,
            [
                "Page.getLayoutMetrics",
                "Runtime.evaluate",
                "Page.captureScreenshot",
                "Page.getLayoutMetrics",
                "Runtime.evaluate",
            ]
        );
        assert_eq!(driver.pipe.writes[2]["params"]["format"], "png");
        assert_eq!(driver.pipe.writes[2]["params"]["fromSurface"], true);
        assert_eq!(
            driver.pipe.writes[2]["params"]["captureBeyondViewport"],
            false
        );
        assert!(
            driver.pipe.writes[2]["params"].get("clip").is_none(),
            "a viewport under the vision cap must not send a clip"
        );
    }

    #[test]
    fn screenshot_clip_scale_is_none_when_full_or_already_within_the_cap() {
        assert_eq!(screenshot_clip_scale(3136.0, 1568.0, 1.0, false), Some(0.5));
        assert_eq!(screenshot_clip_scale(3136.0, 1568.0, 1.0, true), None);
        assert_eq!(screenshot_clip_scale(800.0, 600.0, 1.0, false), None);
        assert_eq!(
            screenshot_clip_scale(f64::from(VISION_LONG_EDGE_PX), 100.0, 1.0, false),
            None
        );
        assert_eq!(screenshot_clip_scale(1200.0, 953.0, 2.0, true), None);
    }

    fn vision_token_count(width_px: f64, height_px: f64) -> f64 {
        let patch = f64::from(VISION_PATCH_PX);
        (width_px / patch).ceil() * (height_px / patch).ceil()
    }

    fn assert_clip_scale_is_maximal_within_vision_limits(
        width_css: f64,
        height_css: f64,
        device_scale_factor: f64,
    ) {
        let scale = screenshot_clip_scale(width_css, height_css, device_scale_factor, false)
            .expect("fixture must exceed a vision limit so a scale is sent");
        let width_px = width_css * scale * device_scale_factor;
        let height_px = height_css * scale * device_scale_factor;
        let tokens = vision_token_count(width_px, height_px);
        let edge = f64::from(VISION_LONG_EDGE_PX);
        let cap = f64::from(VISION_TOKEN_CAP);
        assert!(
            tokens <= cap,
            "produced {width_px}x{height_px} costs {tokens} tokens"
        );
        assert!(
            width_px <= edge && height_px <= edge,
            "produced {width_px}x{height_px} exceeds the long-edge cap"
        );

        let wider = width_px + 1.0;
        let taller = height_px * (wider / width_px);
        let tokens_one_step = vision_token_count(wider, taller);
        assert!(
            tokens_one_step > cap || wider > edge || taller > edge,
            "one pixel wider ({wider}x{taller}, {tokens_one_step} tokens) still fits"
        );
    }

    #[test]
    fn screenshot_clip_scale_keeps_a_wide_capture_within_the_token_cap() {
        // 1200x953 CSS at device scale 2 -> 2400x1906 native. Scaling only to
        // the long-edge cap yields 1568x1245, which costs 56*45 = 2520 tokens.
        let width_css = 1200.0;
        let height_css = 953.0;
        let dpr = 2.0;
        let scale = screenshot_clip_scale(width_css, height_css, dpr, false)
            .expect("native 2400x1906 exceeds the token cap");
        let edge_only = f64::from(VISION_LONG_EDGE_PX) / (width_css * dpr);
        assert_ne!(
            scale, edge_only,
            "must not stop at the long-edge cap while tokens still overflow"
        );
        assert_clip_scale_is_maximal_within_vision_limits(width_css, height_css, dpr);
    }

    #[test]
    fn screenshot_clip_scale_keeps_a_tall_capture_within_the_token_cap() {
        // Same viewport rotated. A square would have both limits bind together,
        // so it cannot tell an edge-only scale from a token-capped one.
        assert_clip_scale_is_maximal_within_vision_limits(953.0, 1200.0, 2.0);
    }

    #[test]
    fn screenshot_clip_scale_shrinks_when_edges_fit_but_tokens_do_not() {
        // 1568x1245: both edges are legal, but 56*45 = 2520 tokens. An
        // edge-only rule returns None and ships an image the API downscales.
        assert_clip_scale_is_maximal_within_vision_limits(1568.0, 1245.0, 1.0);
    }

    fn oversized_css_viewport() -> (Value, Value) {
        // pageX/Y differ from offsetX/Y on purpose: clip origin is document
        // coordinates. Using the visual-viewport offset would capture the wrong
        // region of a scrolled page and still look like a plausible clip.
        let css_viewport = json!({
            "offsetX": 10.0,
            "offsetY": 20.0,
            "pageX": 40.0,
            "pageY": 80.0,
            "clientWidth": 3136.0,
            "clientHeight": 1568.0,
            "scale": 1.0
        });
        let device_viewport = json!({
            "offsetX": 20.0,
            "offsetY": 40.0,
            "pageX": 80.0,
            "pageY": 160.0,
            "clientWidth": 6272.0,
            "clientHeight": 3136.0,
            "scale": 1.0
        });
        (css_viewport, device_viewport)
    }

    fn screenshot_driver_with_viewport(
        css_viewport: Value,
        device_viewport: Value,
        dpr: f64,
    ) -> CdpNavigationDriver<FakePipe> {
        const ONE_BY_ONE_PNG_B64: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==";
        let metrics = json!({
            "cssVisualViewport": css_viewport,
            "visualViewport": device_viewport,
        });
        let frames = [
            json!({"id":1,"sessionId":"session-own","result":metrics.clone()}),
            json!({"id":2,"sessionId":"session-own","result":{"result":{"type":"number","value":dpr}}}),
            json!({"id":3,"sessionId":"session-own","result":{"data":ONE_BY_ONE_PNG_B64}}),
            json!({"id":4,"sessionId":"session-own","result":metrics}),
            json!({"id":5,"sessionId":"session-own","result":{"result":{"type":"number","value":dpr}}}),
        ];
        attached_driver(frames)
    }

    #[test]
    fn screenshot_sends_a_document_clip_that_lands_the_long_edge_on_the_vision_cap() {
        let (css_viewport, device_viewport) = oversized_css_viewport();
        let mut driver = screenshot_driver_with_viewport(css_viewport, device_viewport, 1.0);
        let mut clock = FakeClock::new();

        driver
            .screenshot_for_test("route-own", 7, 100, false, &mut clock)
            .expect("the CDP responses describe a coherent screenshot");

        let clip = &driver.pipe.writes[2]["params"]["clip"];
        assert_eq!(
            clip["x"].as_f64(),
            Some(40.0),
            "clip used layout offset rather than document origin: {clip}"
        );
        assert_eq!(
            clip["y"].as_f64(),
            Some(80.0),
            "clip used layout offset rather than document origin: {clip}"
        );
        assert_eq!(clip["width"].as_f64(), Some(3136.0));
        assert_eq!(clip["height"].as_f64(), Some(1568.0));
        assert_eq!(clip["scale"].as_f64(), Some(0.5));
    }

    #[test]
    fn screenshot_full_omits_the_clip_even_when_the_viewport_exceeds_the_vision_cap() {
        let (css_viewport, device_viewport) = oversized_css_viewport();
        let mut driver = screenshot_driver_with_viewport(css_viewport, device_viewport, 1.0);
        let mut clock = FakeClock::new();

        driver
            .screenshot_for_test("route-own", 7, 100, true, &mut clock)
            .expect("the CDP responses describe a coherent screenshot");

        assert!(
            driver.pipe.writes[2]["params"].get("clip").is_none(),
            "full must skip resize rather than send a clip: {}",
            driver.pipe.writes[2]["params"]
        );
    }

    #[test]
    fn missing_element_attributes_make_the_dom_projection_unknown() {
        let result = json!({"nodes":[{
            "nodeId": 1,
            "nodeType": 1,
            "backendNodeId": 10,
            "nodeName": "BUTTON",
            "localName": "button"
        }]});
        assert_eq!(
            parse_flattened_dom_nodes(result.as_object().unwrap()),
            Err(ClassificationUnavailable::AttributesMissing { node_id: 1 })
        );
    }

    /// A page URL with a path: the shape a session's navigation tracker
    /// records and the snapshot path hands to classification. Fixtures that
    /// passed a bare origin here are how a URL-shaped input went unnoticed.
    const PAGE_URL: &str = "https://login.example/account";

    /// `DOM.getFlattenedDocument` of a loopback page holding a same-origin
    /// link, a cross-origin link, a relative link, a plain button and a login
    /// form, captured from headless Chrome by `examples/classify_live.rs`.
    const LOOPBACK_CAPTURE: &str = include_str!("fixtures/loopback_flattened_document.json");

    /// Drive the production snapshot path over an AX tree of a root (backend
    /// 10) and one button (backend 60, ref `e2`) in `frame-main`, answering the
    /// DOM reads with `dom_frames`.
    fn snapshot_refs(dom_frames: Vec<Value>, context: Option<(u64, &str)>) -> Vec<RefRecord> {
        let mut frames = vec![
            json!({"id":1,"sessionId":"session-own","result":{}}),
            json!({"id":2,"sessionId":"session-own","result":{"node":ax_node("root","RootWebArea","Login", &["button"], 10, Some("frame-main"))}}),
            json!({"id":3,"sessionId":"session-own","result":{"nodes":[
                ax_node("button","button","Sign in", &[], 60, None),
            ]}}),
        ];
        frames.extend(dom_frames);
        let mut driver = attached_driver(frames);
        driver
            .snapshot_with_clock(
                "route-own",
                SnapshotKind::Ax,
                1_000,
                context,
                &mut FakeClock::new(),
            )
            .expect("the AX tree is coherent")
            .refs
    }

    fn dom_enabled() -> Value {
        json!({"id":4,"sessionId":"session-own","result":{}})
    }

    fn dom_frames(nodes: Value) -> Vec<Value> {
        vec![
            dom_enabled(),
            json!({"id":5,"sessionId":"session-own","result":{"nodes":nodes}}),
        ]
    }

    /// Retain `refs` on a plane that withholds any reply its schema does not
    /// declare, then click ref `e2` through the serving boundary. The grant
    /// covers the page at tier 4 and discloses no hazard.
    async fn click_reply(refs: Vec<RefRecord>, severity: Value) -> Value {
        let route = cerebellum_core::identity::RouteIdentity::from_bind(
            &subc_protocol::BindIdentity::new("/tmp/project", "test", "conversation"),
            &Some(subc_protocol::Principal::Direct),
        );
        let grants =
            crate::authorization::GrantStore::new([crate::authorization::ActionGrant::new(
                "classification-test-grant",
                1,
                route.conversation_key.clone(),
                crate::authorization::Severity::new(4, false, false),
                ["https://login.example"],
            )]);
        let plane = crate::browser::BrowserPlane::with_grants(grants)
            .with_result_schema_enforcement(
                crate::computer_capability::ResultSchemaEnforcement::Withhold,
            );
        plane.open_context(route.clone()).await.unwrap();
        plane
            .same_document_url(
                &route,
                PAGE_URL,
                crate::snapshot_store::SameDocumentChange::ReplaceState,
            )
            .await
            .unwrap();
        let retained = plane
            .retain_text_snapshot(&route, SnapshotKind::Ax, &[], None, refs, 4096)
            .await
            .unwrap();
        plane
            .serve(
                &route,
                crate::browser::BrowserCapability::Click,
                &json!({
                    "ref": "e2",
                    "snapshot_id": retained["snapshot_id"],
                    "intent": "press the target",
                    "severity": severity,
                }),
            )
            .await
            .unwrap_or_else(|error| panic!("the click reply broke its declared schema: {error:?}"))
    }

    #[tokio::test]
    async fn each_unavailable_classification_names_its_cause_on_the_click_refusal() {
        use ClassificationUnavailable as Unavailable;

        let html = flattened_dom_node(1, None, 10, "html", &[]);
        let button = flattened_dom_node(2, Some(1), 60, "button", &["type", "submit"]);
        let button_with = |attributes: Value| {
            let mut node = button.clone();
            node["attributes"] = attributes;
            node
        };
        let button_without = |fields: &[&str]| {
            let mut node = button.clone();
            for field in fields {
                node.as_object_mut().unwrap().remove(*field);
            }
            node
        };
        let refused = |id: u64| json!({"id":id,"sessionId":"session-own","error":{"code":-32000,"message":"refused"}});
        let page = Some((7, PAGE_URL));

        // Each fixture breaks exactly one step, and the expected facts are
        // written out rather than derived, so a neighbouring variant, a
        // generic reason, or no reason at all each fail a different case.
        // (DOM answers, classification context, expected reason, its facts)
        type Case<'a> = (Vec<Value>, Option<(u64, &'a str)>, Unavailable, Value);
        let cases: Vec<Case> = vec![
            (vec![], None, Unavailable::NotCaptured, json!({})),
            (
                vec![],
                Some((7, "about:blank")),
                Unavailable::DocumentOriginUnavailable,
                json!({}),
            ),
            (
                vec![refused(4)],
                page,
                Unavailable::DomEnableRefused,
                json!({}),
            ),
            (
                vec![dom_enabled(), refused(5)],
                page,
                Unavailable::FlattenedDocumentRefused,
                json!({}),
            ),
            // No answer to getFlattenedDocument: the read runs out of time.
            (
                vec![dom_enabled()],
                page,
                Unavailable::DomReadFailed,
                json!({}),
            ),
            (
                vec![
                    dom_enabled(),
                    json!({"id":5,"sessionId":"session-own","result":{}}),
                ],
                page,
                Unavailable::FlattenedNodesMissing,
                json!({}),
            ),
            (
                dom_frames(json!([html.clone(), 5])),
                page,
                Unavailable::NodeNotObject { index: 1 },
                json!({"index":1}),
            ),
            (
                dom_frames(json!([html.clone(), button_without(&["nodeType"])])),
                page,
                Unavailable::NodeFieldInvalid {
                    index: 1,
                    field: "nodeType",
                },
                json!({"index":1,"field":"nodeType"}),
            ),
            (
                dom_frames(json!([html.clone(), button_without(&["nodeId"])])),
                page,
                Unavailable::NodeFieldInvalid {
                    index: 1,
                    field: "nodeId",
                },
                json!({"index":1,"field":"nodeId"}),
            ),
            (
                dom_frames(json!([html.clone(), button_without(&["backendNodeId"])])),
                page,
                Unavailable::NodeFieldInvalid {
                    index: 1,
                    field: "backendNodeId",
                },
                json!({"index":1,"field":"backendNodeId"}),
            ),
            (
                dom_frames(json!([
                    html.clone(),
                    button_without(&["localName", "nodeName"])
                ])),
                page,
                Unavailable::NodeFieldInvalid {
                    index: 1,
                    field: "localName",
                },
                json!({"index":1,"field":"localName"}),
            ),
            (
                dom_frames(json!([html.clone(), button_without(&["attributes"])])),
                page,
                Unavailable::AttributesMissing { node_id: 2 },
                json!({"node_id":2}),
            ),
            (
                dom_frames(json!([
                    html.clone(),
                    button_with(json!(["type", "submit", "disabled"]))
                ])),
                page,
                Unavailable::AttributesOddLength {
                    node_id: 2,
                    length: 3,
                },
                json!({"node_id":2,"length":3}),
            ),
            (
                dom_frames(json!([html.clone(), button_with(json!(["type", 5]))])),
                page,
                Unavailable::AttributeNotString {
                    node_id: 2,
                    position: 1,
                },
                json!({"node_id":2,"position":1}),
            ),
            (
                dom_frames(json!([
                    html.clone(),
                    button_with(json!(["type", "submit", "TYPE", "button"]))
                ])),
                page,
                Unavailable::DuplicateAttribute { node_id: 2 },
                json!({"node_id":2}),
            ),
            (
                dom_frames(json!([
                    html.clone(),
                    button.clone(),
                    flattened_dom_node(2, Some(1), 70, "span", &[]),
                ])),
                page,
                Unavailable::DuplicateNodeId { node_id: 2 },
                json!({"node_id":2}),
            ),
            (
                dom_frames(json!([
                    html.clone(),
                    button.clone(),
                    flattened_dom_node(3, Some(1), 60, "span", &[]),
                ])),
                page,
                Unavailable::DuplicateBackendNodeId {
                    backend_node_id: 60,
                },
                json!({"backend_node_id":60}),
            ),
            (
                dom_frames(json!([
                    html.clone(),
                    flattened_dom_node(2, Some(1), 70, "button", &[]),
                ])),
                page,
                Unavailable::TargetNotInDocument {
                    backend_node_id: 60,
                },
                json!({"backend_node_id":60}),
            ),
            // The root names the button as its parent, so walking up from the
            // button comes back to it.
            (
                dom_frames(json!([
                    flattened_dom_node(1, Some(2), 10, "html", &[]),
                    button.clone(),
                ])),
                page,
                Unavailable::ComposedParentCycle { node_id: 2 },
                json!({"node_id":2}),
            ),
            // A complete projection whose link has no host: the classifier
            // itself refuses the destination.
            (
                dom_frames(json!([
                    html.clone(),
                    flattened_dom_node(2, Some(1), 60, "a", &["href", "https://"]),
                ])),
                page,
                Unavailable::ClassifierRejected(
                    classification::ClassificationError::InvalidDestination,
                ),
                json!({"classifier_error":"invalid_destination"}),
            ),
        ];

        for (dom, context, expected, expected_facts) in cases {
            // Written out rather than read from `reason_code`, so a code that
            // drifts to a generic name is caught on the wire.
            let code = match &expected {
                Unavailable::NotCaptured => "not_captured",
                Unavailable::DocumentOriginUnavailable => "document_origin_unavailable",
                Unavailable::DomEnableRefused => "dom_enable_refused",
                Unavailable::FlattenedDocumentRefused => "flattened_document_refused",
                Unavailable::DomReadFailed => "dom_read_failed",
                Unavailable::FlattenedNodesMissing => "flattened_nodes_missing",
                Unavailable::NodeNotObject { .. } => "node_not_object",
                Unavailable::NodeFieldInvalid { .. } => "node_field_invalid",
                Unavailable::AttributesMissing { .. } => "attributes_missing",
                Unavailable::AttributesOddLength { .. } => "attributes_odd_length",
                Unavailable::AttributeNotString { .. } => "attribute_not_string",
                Unavailable::DuplicateAttribute { .. } => "duplicate_attribute",
                Unavailable::DuplicateNodeId { .. } => "duplicate_node_id",
                Unavailable::DuplicateBackendNodeId { .. } => "duplicate_backend_node_id",
                Unavailable::TargetNotInDocument { .. } => "target_not_in_document",
                Unavailable::ComposedParentCycle { .. } => "composed_parent_cycle",
                Unavailable::ClassifierRejected(_) => "classifier_rejected",
            };
            let refs = snapshot_refs(dom, context);
            assert_eq!(
                refs[1].classification,
                Err(expected.clone()),
                "snapshot classification for the {code} fixture"
            );

            let reply = click_reply(
                refs,
                json!({"tier": 2, "credential": false, "financial": false}),
            )
            .await;
            assert_eq!(reply["outcome"], "hazard_not_disclosed", "{code}: {reply}");
            assert_eq!(
                reply["detail"]["missing_hazard"], "unverified_form_contents",
                "{code}: {reply}"
            );
            assert_eq!(
                reply["detail"]["classification_unavailable"], code,
                "{code}: {reply}"
            );
            assert_eq!(
                reply["detail"]["classification_unavailable_facts"], expected_facts,
                "{code}: {reply}"
            );
        }
    }

    #[test]
    fn a_captured_loopback_page_classifies_links_and_buttons_and_keeps_the_login_hazard() {
        use crate::authorization::{
            computed_required_severity, target_hazards, Action, HazardClass, Severity,
        };

        let capture: Value = serde_json::from_str(LOOPBACK_CAPTURE).unwrap();
        let document_url = capture["document_url"].as_str().unwrap();
        // The capture keeps the URL the browser reported, path included, which
        // is the shape that used to make every target unclassifiable.
        assert_ne!(
            classification::canonical_origin(document_url).as_deref(),
            Some(document_url),
            "the fixture must hold a URL, not a bare origin: {document_url}"
        );
        let result = capture["result"].as_object().unwrap();
        let classify = |element_id: &str| {
            let backend_node_id = result["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|node| {
                    node["attributes"].as_array().is_some_and(|attributes| {
                        attributes
                            .chunks(2)
                            .any(|pair| pair[0] == "id" && pair[1] == element_id)
                    })
                })
                .and_then(|node| node["backendNodeId"].as_u64())
                .unwrap_or_else(|| panic!("#{element_id} is in the capture"));
            let identity = BackendNodeIdentity::new(
                capture["target_id"].as_str().unwrap(),
                capture["frame_id"].as_str().unwrap(),
                backend_node_id,
            )
            .unwrap();
            classify_flattened_document(result, &identity, 1, document_url)
                .unwrap_or_else(|reason| panic!("#{element_id} did not classify: {reason}"))
        };
        let required = |record: &NonTypeClassificationRecord| {
            computed_required_severity(Action::Click, Some(record))
                .unwrap()
                .0
        };
        let hazards = |record: &NonTypeClassificationRecord| {
            target_hazards(Action::Click, Some(record)).unwrap()
        };

        for element_id in ["same", "relative", "plain"] {
            let record = classify(element_id);
            assert!(hazards(&record).is_empty(), "#{element_id}: {record:?}");
            assert_eq!(
                required(&record),
                Severity::new(2, false, false),
                "#{element_id}"
            );
        }

        // A classified cross-origin link still requires tier 4, because
        // activating it leaves the origin the grant was asked for.
        let cross = classify("cross");
        assert!(hazards(&cross).is_empty(), "{cross:?}");
        assert_eq!(
            cross.activation_destination_origin.as_deref(),
            Some("https://cross-origin.invalid")
        );
        assert_eq!(required(&cross), Severity::new(4, false, false));

        let submit = classify("submit");
        assert!(submit.activation_invokes_form_submit);
        assert_eq!(
            hazards(&submit),
            BTreeSet::from([HazardClass::CredentialFormSubmit])
        );
        assert_eq!(required(&submit), Severity::new(4, true, false));
    }

    #[tokio::test]
    async fn a_click_below_the_floor_reports_the_severity_authorization_computed() {
        let html = flattened_dom_node(1, None, 10, "html", &[]);
        let below_floor = json!({"tier": 1, "credential": false, "financial": false});

        // A classified cross-origin link: its computed requirement (tier 4)
        // differs from both the floor (2) and the unclassified maximum, so
        // only the value authorization computed matches.
        let refs = snapshot_refs(
            dom_frames(json!([
                html,
                flattened_dom_node(
                    2,
                    Some(1),
                    60,
                    "a",
                    &["href", "https://elsewhere.example/x"]
                ),
            ])),
            Some((7, PAGE_URL)),
        );
        let record = *refs[1].classification.clone().expect("the link classifies");
        let (computed, _) = crate::authorization::computed_required_severity(
            crate::authorization::Action::Click,
            Some(&record),
        )
        .unwrap();
        assert_eq!(
            computed,
            crate::authorization::Severity::new(4, false, false)
        );
        let reply = click_reply(refs.clone(), below_floor.clone()).await;
        assert_eq!(reply["outcome"], "invalid_request", "{reply}");
        assert_eq!(
            reply["detail"]["reason_code"], "severity_below_floor",
            "{reply}"
        );
        assert_eq!(
            reply["detail"]["required"],
            json!({"tier": computed.tier, "credential": computed.credential, "financial": computed.financial}),
            "{reply}"
        );
        assert!(
            reply["detail"].get("classification_unavailable").is_none(),
            "{reply}"
        );

        // The same link at the floor passes authorization and stops only for
        // want of a browser session: an ordinary link is no longer refused as
        // an unverified form.
        let reply = click_reply(
            refs,
            json!({"tier": 2, "credential": false, "financial": false}),
        )
        .await;
        assert_eq!(reply["outcome"], "no_session", "{reply}");

        // An unclassified target computes the strongest requirement, and the
        // refusal names why it was unclassified.
        let refs = snapshot_refs(vec![], Some((7, "about:blank")));
        let reply = click_reply(refs, below_floor).await;
        assert_eq!(
            reply["detail"]["reason_code"], "severity_below_floor",
            "{reply}"
        );
        assert_eq!(
            reply["detail"]["required"],
            json!({"tier": 4, "credential": true, "financial": true}),
            "{reply}"
        );
        assert_eq!(
            reply["detail"]["classification_unavailable"], "document_origin_unavailable",
            "{reply}"
        );
    }

    #[tokio::test]
    async fn a_point_click_below_the_floor_reports_the_severity_authorization_computed() {
        let route = cerebellum_core::identity::RouteIdentity::from_bind(
            &subc_protocol::BindIdentity::new("/tmp/project", "test", "conversation"),
            &Some(subc_protocol::Principal::Direct),
        );
        let plane = crate::browser::BrowserPlane::new().with_result_schema_enforcement(
            crate::computer_capability::ResultSchemaEnforcement::Withhold,
        );
        plane.open_context(route.clone()).await.unwrap();
        let view = ViewportObservation::new(
            0,
            TransformInputs::from_values(0.0, 0.0, 1.0, 1.0, 1.0, 1.0),
        );
        let retained = plane
            .retain_screenshot(
                &route,
                crate::coordinate::ScreenshotPayload::new(
                    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==",
                    1,
                    1,
                ),
                view,
                view,
                false,
            )
            .await
            .unwrap();
        let (computed, _) = crate::authorization::computed_required_severity(
            crate::authorization::Action::ClickPoint,
            None,
        )
        .unwrap();
        let reply = plane
            .serve(
                &route,
                crate::browser::BrowserCapability::ClickPoint,
                &json!({
                    "snapshot_id": retained["snapshot_id"],
                    "x_px": 0,
                    "y_px": 0,
                    "image_width_px": 1,
                    "image_height_px": 1,
                    "intent": "press the pixel",
                    "severity": {"tier": 1, "credential": false, "financial": false},
                }),
            )
            .await
            .unwrap_or_else(|error| panic!("the reply broke its declared schema: {error:?}"));
        assert_eq!(
            reply["detail"]["reason_code"], "severity_below_floor",
            "{reply}"
        );
        assert_eq!(
            reply["detail"]["required"],
            json!({"tier": computed.tier, "credential": computed.credential, "financial": computed.financial}),
            "{reply}"
        );
    }

    #[test]
    fn classified_snapshot_pins_form_hazards_beside_the_target_ref() {
        let frames = [
            json!({"id":1,"sessionId":"session-own","result":{}}),
            json!({"id":2,"sessionId":"session-own","result":{"node":ax_node("root","RootWebArea","Login", &["button"], 10, Some("frame-main"))}}),
            json!({"id":3,"sessionId":"session-own","result":{"nodes":[
                ax_node("button","button","Sign in", &[], 60, None),
            ]}}),
            json!({"id":4,"sessionId":"session-own","result":{}}),
            json!({"id":5,"sessionId":"session-own","result":{"nodes":[
                flattened_dom_node(1, None, 10, "html", &[]),
                flattened_dom_node(2, Some(1), 30, "form", &[]),
                flattened_dom_node(3, Some(2), 40, "input", &["type", "password"]),
                flattened_dom_node(4, Some(2), 60, "button", &["type", "submit"]),
            ]}}),
        ];
        let mut driver = attached_driver(frames);
        let observation = driver
            .snapshot_with_clock(
                "route-own",
                SnapshotKind::Ax,
                1_000,
                Some((7, "https://login.example")),
                &mut FakeClock::new(),
            )
            .unwrap();
        let record = observation.refs[1]
            .classification
            .as_ref()
            .expect("the button ref carries the same-epoch classification");

        assert!(record.activation_invokes_form_submit);
        assert!(record.credential);
        assert!(!record.financial);
        assert_eq!(record.document_epoch, 7);
    }

    #[test]
    fn real_dom_projection_feeds_the_frozen_classifier_for_login_and_payment_forms() {
        let frames = [
            json!({"id":1,"sessionId":"session-own","result":{}}),
            json!({"id":2,"sessionId":"session-own","result":{"nodes":[
                flattened_dom_node(1, None, 10, "html", &[]),
                flattened_dom_node(2, Some(1), 20, "body", &[]),
                flattened_dom_node(3, Some(2), 30, "form", &["id", "checkout", "action", "/pay"]),
                flattened_dom_node(4, Some(3), 40, "input", &["type", "password", "autocomplete", "current-password"]),
                flattened_dom_node(5, Some(3), 50, "input", &["autocomplete", "cc-number"]),
                flattened_dom_node(6, Some(3), 60, "button", &["type", "submit"]),
            ]}}),
        ];
        let mut driver = attached_driver(frames);
        let identity = BackendNodeIdentity::new("target-own", "frame-main", 60).unwrap();
        let record = driver
            .classify_click_for_test(
                "route-own",
                &identity,
                7,
                "https://shop.example",
                1_000,
                &mut FakeClock::new(),
            )
            .unwrap()
            .expect("the complete DOM projection classifies");

        assert!(record.activation_invokes_form_submit);
        assert!(record.credential);
        assert!(record.financial);
        assert_eq!(record.required_tier, crate::authorization::MUTATE_DURABLE);
        assert_eq!(
            driver
                .pipe
                .writes
                .iter()
                .map(|write| write["method"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["DOM.enable", "DOM.getFlattenedDocument"]
        );
    }

    #[test]
    fn an_unavailable_dom_classification_is_explicitly_unknown() {
        let frames = [json!({
            "id":1,
            "sessionId":"session-own",
            "error":{"code":-32601,"message":"unsupported"}
        })];
        let mut driver = attached_driver(frames);
        let identity = BackendNodeIdentity::new("target-own", "frame-main", 60).unwrap();
        assert_eq!(
            driver
                .classify_click_for_test(
                    "route-own",
                    &identity,
                    7,
                    "https://shop.example",
                    1_000,
                    &mut FakeClock::new(),
                )
                .unwrap(),
            Err(ClassificationUnavailable::DomEnableRefused)
        );
    }

    #[test]
    fn final_classification_revalidation_refuses_before_input() {
        let initial_nodes = json!({"nodes":[
            flattened_dom_node(1, None, 10, "html", &[]),
            flattened_dom_node(2, Some(1), 20, "form", &[]),
            flattened_dom_node(3, Some(2), 30, "input", &["type", "password"]),
            flattened_dom_node(4, Some(2), 42, "button", &["type", "submit"]),
        ]});
        let revalidated_nodes = json!({"nodes":[
            flattened_dom_node(1, None, 10, "html", &[]),
            flattened_dom_node(2, Some(1), 20, "form", &[]),
            flattened_dom_node(3, Some(2), 30, "input", &["type", "text"]),
            flattened_dom_node(4, Some(2), 42, "button", &["type", "submit"]),
        ]});
        let mut driver = attached_driver([
            json!({"id":1,"sessionId":"session-own","result":{}}),
            json!({"id":2,"sessionId":"session-own","result":initial_nodes}),
            json!({"id":3,"sessionId":"session-own","result":{"quads":[[10.0,20.0,34.0,20.0,34.0,52.0,10.0,52.0]]}}),
            json!({"id":4,"sessionId":"session-own","result":{}}),
            json!({"id":5,"sessionId":"session-own","result":{"quads":[[10.0,20.0,34.0,20.0,34.0,52.0,10.0,52.0]]}}),
            json!({"id":6,"sessionId":"session-own","result":layout_metrics(0.0, 0.0, 1280.0, 713.0)}),
            json!({"id":7,"sessionId":"session-own","result":{"backendNodeId":42,"frameId":"frame-main"}}),
            json!({"id":8,"sessionId":"session-own","result":{}}),
            json!({"id":9,"sessionId":"session-own","result":revalidated_nodes}),
        ]);
        let identity = BackendNodeIdentity::new("target-own", "frame-main", 42).unwrap();
        let mut clock = FakeClock::new();
        let initial = driver
            .classify_click_for_test(
                "route-own",
                &identity,
                7,
                "https://login.example",
                1_000,
                &mut clock,
            )
            .unwrap()
            .unwrap();
        assert!(initial.credential);
        let mut input_events = Vec::new();
        let result = driver.click_with_clock(
            "route-own",
            &identity,
            1_000,
            &mut |event| input_events.push(event),
            Some((7, "https://login.example", Some(&initial))),
            &mut clock,
        );

        assert_eq!(result, Err(ClickDriveError::ClassificationChanged));
        assert!(input_events.is_empty());
        assert!(driver
            .pipe
            .writes
            .iter()
            .all(|write| write["method"] != "Input.dispatchMouseEvent"));
    }

    #[test]
    fn click_dispatches_mouse_input_at_the_resolved_content_quad_center() {
        let quad = json!([[10.0, 20.0, 34.0, 20.0, 34.0, 52.0, 10.0, 52.0]]);
        let frames = [
            json!({"id":1,"sessionId":"session-own","result":{"quads":quad.clone()}}),
            json!({"id":2,"sessionId":"session-own","result":{}}),
            json!({"id":3,"sessionId":"session-own","result":{"quads":quad}}),
            json!({"id":4,"sessionId":"session-own","result":layout_metrics(0.0, 0.0, 1280.0, 713.0)}),
            json!({"id":5,"sessionId":"session-own","result":{"backendNodeId":42,"frameId":"frame-main"}}),
            json!({"id":6,"sessionId":"session-own","result":{}}),
            json!({"id":7,"sessionId":"session-own","result":{}}),
            json!({"id":8,"sessionId":"session-own","result":{}}),
            json!({"id":9,"sessionId":"session-own","result":{}}),
        ];
        let mut driver = attached_driver(frames);
        let identity = BackendNodeIdentity::new("target-own", "frame-main", 42).unwrap();
        let mut input_events = Vec::new();
        let mut clock = FakeClock::new();

        let outcome = driver
            .click_for_test(
                "route-own",
                &identity,
                1_000,
                &mut |event| input_events.push(event),
                &mut clock,
            )
            .unwrap();

        let position = BrowserClickPosition {
            x_css: 22.0,
            y_css: 36.0,
        };
        assert_eq!(
            outcome,
            BrowserClickOutcome::Clicked {
                position,
                navigation: ClickNavigation::NoneObserved { window_ms: 100 },
            }
        );
        assert_eq!(
            input_events,
            vec![
                BrowserInputEvent::Press(position),
                BrowserInputEvent::Release(position),
            ]
        );
        let writes = &driver.pipe.writes;
        assert_eq!(writes.len(), 9);
        assert_eq!(writes[0]["method"], "DOM.getContentQuads");
        assert_eq!(writes[1]["method"], "DOM.scrollIntoViewIfNeeded");
        assert_eq!(writes[1]["params"]["backendNodeId"], 42);
        assert_eq!(writes[2]["method"], "DOM.getContentQuads");
        assert_eq!(writes[3]["method"], "Page.getLayoutMetrics");
        assert_eq!(writes[4]["method"], "DOM.getNodeForLocation");
        assert_eq!(writes[4]["params"]["x"], 22);
        assert_eq!(writes[4]["params"]["y"], 36);
        assert_eq!(writes[5]["method"], "Page.enable");
        assert_eq!(writes[6]["method"], "Network.enable");
        assert_eq!(writes[7]["method"], "Input.dispatchMouseEvent");
        assert_eq!(writes[7]["params"]["type"], "mousePressed");
        assert_eq!(writes[8]["method"], "Input.dispatchMouseEvent");
        assert_eq!(writes[8]["params"]["type"], "mouseReleased");
    }

    #[test]
    fn below_fold_click_refetches_after_scroll_and_lands() {
        let frames = [
            json!({"id":1,"sessionId":"session-own","result":{"quads":[[130.0,5000.0,170.0,5000.0,170.0,5040.0,130.0,5040.0]]}}),
            json!({"id":2,"sessionId":"session-own","result":{}}),
            json!({"id":3,"sessionId":"session-own","result":{"quads":[[130.0,50.0,170.0,50.0,170.0,90.0,130.0,90.0]]}}),
            json!({"id":4,"sessionId":"session-own","result":layout_metrics(0.0, 0.0, 1280.0, 713.0)}),
            json!({"id":5,"sessionId":"session-own","result":{"backendNodeId":42,"frameId":"frame-main"}}),
            json!({"id":6,"sessionId":"session-own","result":{}}),
            json!({"id":7,"sessionId":"session-own","result":{}}),
            json!({"id":8,"sessionId":"session-own","result":{}}),
            json!({"id":9,"sessionId":"session-own","result":{}}),
        ];
        let mut driver = attached_driver(frames);
        let identity = BackendNodeIdentity::new("target-own", "frame-main", 42).unwrap();
        let mut input_events = Vec::new();

        let outcome = driver
            .click_for_test(
                "route-own",
                &identity,
                1_000,
                &mut |event| input_events.push(event),
                &mut FakeClock::new(),
            )
            .unwrap();

        assert_eq!(
            outcome,
            BrowserClickOutcome::Clicked {
                position: BrowserClickPosition {
                    x_css: 150.0,
                    y_css: 70.0,
                },
                navigation: ClickNavigation::NoneObserved { window_ms: 100 },
            }
        );
        assert_eq!(input_events.len(), 2);
        assert_eq!(
            driver.pipe.writes[1]["method"],
            "DOM.scrollIntoViewIfNeeded"
        );
        assert_eq!(driver.pipe.writes[2]["method"], "DOM.getContentQuads");
        assert_eq!(driver.pipe.writes[5]["method"], "Page.enable");
        assert_eq!(driver.pipe.writes[7]["params"]["y"], 70.0);
    }

    #[test]
    fn click_without_an_eligible_content_quad_refuses_without_input_dispatch() {
        let frames = [
            json!({"id":1,"sessionId":"session-own","result":{"quads":[[8.0,13.0,8.0,13.0,8.0,13.0,8.0,13.0]]}}),
            json!({"id":2,"sessionId":"session-own","result":{"backendNodeId":42,"frameId":"frame-main"}}),
            json!({"id":3,"sessionId":"session-own","result":{}}),
            json!({"id":4,"sessionId":"session-own","result":{}}),
        ];
        let mut driver = attached_driver(frames);
        let identity = BackendNodeIdentity::new("target-own", "frame-main", 42).unwrap();
        let mut input_events = Vec::new();
        let mut clock = FakeClock::new();

        let result = driver.click_for_test(
            "route-own",
            &identity,
            1_000,
            &mut |event| input_events.push(event),
            &mut clock,
        );

        assert_eq!(result, Err(ClickDriveError::NoPosition));
        assert!(input_events.is_empty());
        assert_eq!(driver.pipe.writes.len(), 1);
        assert_eq!(driver.pipe.writes[0]["method"], "DOM.getContentQuads");
        assert!(driver
            .pipe
            .writes
            .iter()
            .all(|write| write["method"] != "Input.dispatchMouseEvent"));
    }

    #[test]
    fn click_still_outside_after_successful_scroll_refuses_without_input_dispatch() {
        let below_fold = json!([[130.0, 5000.0, 170.0, 5000.0, 170.0, 5040.0, 130.0, 5040.0]]);
        let frames = [
            json!({"id":1,"sessionId":"session-own","result":{"quads":below_fold.clone()}}),
            json!({"id":2,"sessionId":"session-own","result":{}}),
            json!({"id":3,"sessionId":"session-own","result":{"quads":below_fold}}),
            json!({"id":4,"sessionId":"session-own","result":layout_metrics(0.0, 0.0, 1280.0, 713.0)}),
        ];
        let mut driver = attached_driver(frames);
        let identity = BackendNodeIdentity::new("target-own", "frame-main", 42).unwrap();
        let mut input_events = Vec::new();
        let viewport = InputRect::new(0.0, 0.0, 1280.0, 713.0);
        let position = BrowserClickPosition {
            x_css: 150.0,
            y_css: 5020.0,
        };

        let result = driver.click_for_test(
            "route-own",
            &identity,
            1_000,
            &mut |event| input_events.push(event),
            &mut FakeClock::new(),
        );

        assert_eq!(
            result,
            Err(ClickDriveError::OutsideViewportAfterScroll(
                ViewportRefusal { position, viewport }
            ))
        );
        assert!(input_events.is_empty());
        assert_eq!(
            driver.pipe.writes[1]["method"],
            "DOM.scrollIntoViewIfNeeded"
        );
        assert_eq!(driver.pipe.writes[3]["method"], "Page.getLayoutMetrics");
        assert!(driver
            .pipe
            .writes
            .iter()
            .all(|write| write["method"] != "Input.dispatchMouseEvent"));
    }

    #[test]
    fn click_point_outside_viewport_refuses_without_scrolling_or_input() {
        let mut driver = attached_driver([json!({
            "id":1,
            "sessionId":"session-own",
            "result":layout_metrics(0.0, 0.0, 1280.0, 713.0)
        })]);
        let position = BrowserClickPosition {
            x_css: 150.0,
            y_css: 5020.0,
        };
        let viewport = InputRect::new(0.0, 0.0, 1280.0, 713.0);
        let mut input_events = Vec::new();

        let result = driver.click_point_with_clock(
            "route-own",
            position,
            1_000,
            &mut |event| input_events.push(event),
            &mut FakeClock::new(),
        );

        assert_eq!(
            result,
            Err(ClickPointDriveError::OutsideViewport(ViewportRefusal {
                position,
                viewport,
            }))
        );
        assert!(input_events.is_empty());
        assert_eq!(driver.pipe.writes.len(), 1);
        assert_eq!(driver.pipe.writes[0]["method"], "Page.getLayoutMetrics");
    }

    #[test]
    fn click_with_an_occluded_center_refuses_without_input_dispatch() {
        let quad = json!([[10.0, 20.0, 34.0, 20.0, 34.0, 52.0, 10.0, 52.0]]);
        let frames = [
            json!({"id":1,"sessionId":"session-own","result":{"quads":quad.clone()}}),
            json!({"id":2,"sessionId":"session-own","result":{}}),
            json!({"id":3,"sessionId":"session-own","result":{"quads":quad}}),
            json!({"id":4,"sessionId":"session-own","result":layout_metrics(0.0, 0.0, 1280.0, 713.0)}),
            json!({"id":5,"sessionId":"session-own","result":{"backendNodeId":99,"frameId":"frame-main"}}),
            json!({"id":6,"sessionId":"session-own","result":{"node":{"backendNodeId":42}}}),
        ];
        let mut driver = attached_driver(frames);
        let identity = BackendNodeIdentity::new("target-own", "frame-main", 42).unwrap();
        let mut input_events = Vec::new();
        let mut clock = FakeClock::new();

        let result = driver.click_for_test(
            "route-own",
            &identity,
            1_000,
            &mut |event| input_events.push(event),
            &mut clock,
        );

        assert_eq!(result, Err(ClickDriveError::NoPosition));
        assert!(input_events.is_empty());
        assert_eq!(driver.pipe.writes[5]["method"], "DOM.describeNode");
        assert!(driver
            .pipe
            .writes
            .iter()
            .all(|write| write["method"] != "Input.dispatchMouseEvent"));
    }

    #[test]
    fn snapshot_reads_named_structure_and_retains_a_resolvable_backend_identity() {
        let frames = [
            json!({"id":1,"sessionId":"session-own","result":{}}),
            json!({"id":2,"sessionId":"session-own","result":{"node":ax_node("root","RootWebArea","Snapshot fixture", &["heading","link"], 10, Some("frame-main"))}}),
            json!({
                "method":"Accessibility.loadComplete",
                "sessionId":"session-foreign",
                "targetId":"target-foreign",
                "params":{"root":ax_node("intruder","button","Foreign target", &[], 999, Some("frame-foreign"))}
            }),
            json!({"id":3,"sessionId":"session-own","result":{"nodes":[
                ax_node("heading","heading","Account details", &[], 11, None),
                ax_node("link","link","Read details", &[], 12, None)
            ]}}),
        ];
        let mut driver = attached_driver(frames);
        let observation = driver
            .snapshot_for_test("route-own", SnapshotKind::Ax, 1_000, &mut FakeClock::new())
            .unwrap();

        assert_eq!(
            observation
                .records
                .iter()
                .map(|record| (record.role.as_str(), record.name.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("RootWebArea", "Snapshot fixture"),
                ("heading", "Account details"),
                ("link", "Read details"),
            ]
        );
        assert!(!observation
            .records
            .iter()
            .any(|record| record.name == "Foreign target"));
        assert_eq!(observation.refs[2].captured.reference, "e3");
        assert_eq!(
            observation.refs[2].backend_identity,
            Some(BackendNodeIdentity::new("target-own", "frame-main", 12).unwrap())
        );
        assert!(driver.pipe.writes.iter().all(|command| {
            command.get("sessionId").and_then(Value::as_str) == Some("session-own")
        }));

        let snapshot_id = new_snapshot_id("driver-ref-resolution");
        let mut store = BrowserSnapshotStore::new(1).unwrap();
        store
            .retain_text(TextSnapshot {
                snapshot_id: snapshot_id.clone(),
                kind: SnapshotKind::Ax,
                document_epoch: 7,
                source_origin: "https://snapshot.example".into(),
                content_schema: AX_SCHEMA,
                content: String::new(),
                truncated: false,
                refs_truncated: false,
                refs: observation.refs.clone(),
            })
            .unwrap();
        let captured = observation.refs[2].clone();
        let candidates = [
            RefCandidate {
                identity: captured.backend_identity.clone(),
                frame_path: captured.frame_path.clone(),
                role: "link".into(),
                name: "Read details".into(),
                traversal_index: 2,
            },
            RefCandidate {
                identity: Some(BackendNodeIdentity::new("target-own", "frame-main", 77).unwrap()),
                frame_path: captured.frame_path.clone(),
                role: "button".into(),
                name: "Unrelated action".into(),
                traversal_index: 3,
            },
        ];
        assert_eq!(
            store
                .resolve_ref(&snapshot_id, "e3", 7, &candidates)
                .unwrap(),
            RefResolution::Resolved(Box::new(captured))
        );
    }

    #[test]
    fn dom_full_reads_outer_html_while_preserving_ax_refs() {
        let frames = [
            json!({"id":1,"sessionId":"session-own","result":{}}),
            json!({"id":2,"sessionId":"session-own","result":{"node":ax_node("root","RootWebArea","DOM fixture", &[], 10, Some("frame-main"))}}),
            json!({"id":3,"sessionId":"session-own","result":{"root":{"nodeId":42}}}),
            json!({"id":4,"sessionId":"session-own","result":{"outerHTML":"<main><h1>DOM fixture</h1></main>"}}),
        ];
        let mut driver = attached_driver(frames);
        let observation = driver
            .snapshot_for_test(
                "route-own",
                SnapshotKind::DomFull,
                1_000,
                &mut FakeClock::new(),
            )
            .unwrap();

        assert_eq!(
            observation.dom_text.as_deref(),
            Some("<main><h1>DOM fixture</h1></main>")
        );
        assert_eq!(observation.records[0].name, "DOM fixture");
        assert_eq!(observation.refs[0].captured.reference, "e1");
        assert_eq!(
            driver
                .pipe
                .writes
                .iter()
                .map(|command| command["method"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec![
                "Accessibility.enable",
                "Accessibility.getRootAXNode",
                "DOM.getDocument",
                "DOM.getOuterHTML",
            ]
        );
    }

    #[test]
    fn lossy_limits_mark_incomplete_but_an_ancestor_cycle_does_not() {
        let mut nodes = Some(vec![
            raw_node("a", "heading", "First", &[], 2, None),
            raw_node("b", "button", "Second", &[], 3, None),
        ]);
        let bounded = traverse_ax_tree(
            raw_node(
                "root",
                "RootWebArea",
                "Bounded",
                &["a", "b"],
                1,
                Some("frame-main"),
            ),
            "target-own",
            2,
            64,
            |node_id, _| {
                if node_id != "root" {
                    return Err(NavigationDriveError::CdpFailure);
                }
                nodes.take().ok_or(NavigationDriveError::CdpFailure)
            },
        )
        .unwrap();
        assert_eq!(bounded.records.len(), 2);
        assert!(bounded.ax_truncated);
        assert!(bounded.refs_truncated);

        let depth_bounded = traverse_ax_tree(
            raw_node(
                "root",
                "RootWebArea",
                "Depth bounded",
                &["child"],
                1,
                Some("frame-main"),
            ),
            "target-own",
            10,
            0,
            |_, _| panic!("a depth cut must happen before fetching children"),
        )
        .unwrap();
        assert_eq!(depth_bounded.records.len(), 1);
        assert!(depth_bounded.ax_truncated);
        assert!(depth_bounded.refs_truncated);

        let mut cycle_nodes = Some(vec![raw_node(
            "child",
            "group",
            "Cycle child",
            &["root"],
            2,
            None,
        )]);
        let cycle = traverse_ax_tree(
            raw_node(
                "root",
                "RootWebArea",
                "Cycle root",
                &["child"],
                1,
                Some("frame-main"),
            ),
            "target-own",
            10,
            64,
            |node_id, _| {
                if node_id != "root" {
                    return Err(NavigationDriveError::CdpFailure);
                }
                cycle_nodes.take().ok_or(NavigationDriveError::CdpFailure)
            },
        )
        .unwrap();
        assert_eq!(cycle.records.len(), 2);
        assert!(!cycle.ax_truncated);
        assert!(!cycle.refs_truncated);
    }

    #[test]
    fn main_frame_sets_the_browser_reported_url_and_subframe_cannot_replace_it() {
        let driver = attached_driver([]);
        let mut tracker = Tracker::default();
        let now = Instant::now();
        driver.apply_event(
            "route-own",
            &mut tracker,
            &event(
                "Page.frameNavigated",
                json!({"frame":{"id":"main","url":"https://landed.example/final"}}),
            ),
            now,
        );
        driver.apply_event(
            "route-own",
            &mut tracker,
            &event(
                "Page.frameNavigated",
                json!({"frame":{"id":"ad","parentId":"main","url":"https://ads.example/"}}),
            ),
            now,
        );

        assert_eq!(
            tracker.url_final.as_deref(),
            Some("https://landed.example/final")
        );
    }

    #[test]
    fn another_targets_event_cannot_drive_this_tracker() {
        let driver = attached_driver([]);
        let mut tracker = Tracker::default();
        let mut foreign = event("Page.loadEventFired", json!({}));
        foreign.raw["targetId"] = Value::String("target-foreign".into());
        driver.apply_event("route-own", &mut tracker, &foreign, Instant::now());

        assert!(!tracker.load_observed);
        assert!(tracker.lifecycle.is_empty());
    }

    /// A redirect continuation is not a new request.
    ///
    /// Chrome re-emits `requestWillBeSent` for the SAME request when it
    /// redirects, carrying the response that caused it, and the original never
    /// receives its own `loadingFinished`. Counting the continuation leaves one
    /// request in flight forever, so the navigation never reaches network quiet.
    ///
    /// Measured against Chrome 151 before the fix: `http://example.com` never
    /// settled while `https://example.com/` settled at once. Nearly every
    /// bare-domain URL redirects to https, so this made `wait: "settle"`
    /// unusable for real navigation while passing on pages that do not redirect.
    #[test]
    fn a_redirect_continuation_is_not_counted_as_a_new_request() {
        let driver = attached_driver([]);
        let mut tracker = Tracker::default();
        let now = Instant::now();

        // The original request, then the redirect continuation, then the single
        // completion the browser sends for the whole chain.
        driver.apply_event(
            "route-own",
            &mut tracker,
            &event("Network.requestWillBeSent", json!({})),
            now,
        );
        driver.apply_event(
            "route-own",
            &mut tracker,
            &event(
                "Network.requestWillBeSent",
                json!({"redirectResponse": {"status": 301, "url": "http://example.com/"}}),
            ),
            now,
        );
        driver.apply_event(
            "route-own",
            &mut tracker,
            &event("Network.loadingFinished", json!({})),
            now,
        );
        driver.apply_event(
            "route-own",
            &mut tracker,
            &event("Page.loadEventFired", json!({})),
            now,
        );

        assert!(
            tracker.poll_settlement(now + Duration::from_millis(QUIET_MS + 1)),
            "a redirected navigation never settled: {:?} in flight",
            tracker.inflight_count
        );
    }

    /// The companion: an ordinary second request IS counted.
    ///
    /// Without this, ignoring every `requestWillBeSent` would satisfy the test
    /// above while destroying the in-flight count the settlement rule rests on.
    #[test]
    fn an_ordinary_concurrent_request_is_still_counted() {
        let driver = attached_driver([]);
        let mut tracker = Tracker::default();
        let now = Instant::now();

        driver.apply_event(
            "route-own",
            &mut tracker,
            &event("Network.requestWillBeSent", json!({})),
            now,
        );
        driver.apply_event(
            "route-own",
            &mut tracker,
            &event("Network.requestWillBeSent", json!({})),
            now,
        );
        driver.apply_event(
            "route-own",
            &mut tracker,
            &event("Network.loadingFinished", json!({})),
            now,
        );
        driver.apply_event(
            "route-own",
            &mut tracker,
            &event("Page.loadEventFired", json!({})),
            now,
        );

        assert!(
            !tracker.poll_settlement(now + Duration::from_millis(QUIET_MS + 1)),
            "settled while a request was still in flight"
        );
    }

    #[test]
    fn request_will_be_sent_starts_the_attributed_request() {
        let driver = attached_driver([]);
        let mut tracker = Tracker::default();
        driver.apply_event(
            "route-own",
            &mut tracker,
            &event("Network.requestWillBeSent", json!({})),
            Instant::now(),
        );

        assert_eq!(tracker.inflight_count, 1);
    }

    #[test]
    fn loading_failure_finishes_the_attributed_request() {
        let driver = attached_driver([]);
        let mut tracker = Tracker::default();
        tracker.request_started();
        driver.apply_event(
            "route-own",
            &mut tracker,
            &event("Network.loadingFailed", json!({})),
            Instant::now(),
        );

        assert_eq!(tracker.inflight_count, 0);
    }

    #[test]
    fn every_settlement_condition_is_required() {
        let now = Instant::now();

        let mut no_load = Tracker::default();
        no_load.request_started();
        no_load.request_finished(now);
        assert!(!no_load.poll_settlement(now + Duration::from_millis(QUIET_MS)));

        let mut in_flight = Tracker::default();
        in_flight.load(now);
        // Assign the public count directly so the quiet timestamp remains
        // satisfied and this assertion isolates the in-flight predicate.
        in_flight.inflight_count = 1;
        assert!(!in_flight.poll_settlement(now + Duration::from_millis(QUIET_MS)));

        let mut not_quiet = Tracker::default();
        not_quiet.load(now);
        assert!(!not_quiet.poll_settlement(now + Duration::from_millis(QUIET_MS - 1)));

        let mut complete = Tracker::default();
        complete.load(now);
        assert!(complete.poll_settlement(now + Duration::from_millis(QUIET_MS)));
        assert_eq!(complete.lifecycle, ["load", "network_quiet"]);
    }

    #[test]
    fn enables_page_and_network_before_navigation() {
        let frames = [
            json!({"id":1,"result":{"targetId":"target-own"}}),
            json!({"id":2,"result":{"sessionId":"session-own"}}),
            json!({"id":3,"sessionId":"session-own","result":{}}),
            json!({"id":4,"sessionId":"session-own","result":{}}),
            json!({"id":5,"sessionId":"session-own","result":{}}),
        ];
        let mut driver = driver(frames);
        let mut tracker = Tracker::default();
        driver
            .navigate_for_test(
                "route-own",
                "https://requested.example/",
                NavigationWait::None,
                100,
                &mut tracker,
                &mut FakeClock::new(),
            )
            .unwrap();

        let methods = driver
            .pipe
            .writes
            .iter()
            .map(|write| write["method"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            methods,
            [
                "Target.createTarget",
                "Target.attachToTarget",
                "Page.enable",
                "Network.enable",
                "Page.navigate",
            ]
        );
    }

    #[test]
    fn redirected_main_frame_is_the_final_url_and_subframe_is_ignored() {
        let frames = [
            json!({"id":1,"result":{"targetId":"target-own"}}),
            json!({"id":2,"result":{"sessionId":"session-own"}}),
            json!({"id":3,"sessionId":"session-own","result":{}}),
            json!({"id":4,"sessionId":"session-own","result":{}}),
            json!({"id":5,"sessionId":"session-own","result":{}}),
            json!({"method":"Network.requestWillBeSent","sessionId":"session-own","params":{}}),
            json!({"method":"Page.frameNavigated","sessionId":"session-own","params":{"frame":{"id":"main","url":"https://requested.example/"}}}),
            json!({"method":"Page.frameNavigated","sessionId":"session-own","params":{"frame":{"id":"main","url":"https://landed.example/final"}}}),
            json!({"method":"Page.frameNavigated","sessionId":"session-own","params":{"frame":{"id":"ad","parentId":"main","url":"https://ads.example/"}}}),
            json!({"method":"Network.loadingFinished","sessionId":"session-own","params":{}}),
            json!({"method":"Page.loadEventFired","sessionId":"session-own","params":{}}),
        ];
        let mut driver = driver(frames);
        let mut tracker = Tracker::default();
        tracker.token("navigation_started");
        driver
            .navigate_for_test(
                "route-own",
                "https://requested.example/",
                NavigationWait::Settle,
                1_000,
                &mut tracker,
                &mut FakeClock::new(),
            )
            .unwrap();

        assert!(tracker.settled);
        assert_eq!(
            tracker.url_final.as_deref(),
            Some("https://landed.example/final")
        );
        assert_eq!(
            tracker.lifecycle,
            ["navigation_started", "load", "network_quiet"]
        );
    }

    #[test]
    fn deadline_returns_observed_tokens_without_hanging() {
        let frames = [
            json!({"id":1,"result":{"targetId":"target-own"}}),
            json!({"id":2,"result":{"sessionId":"session-own"}}),
            json!({"id":3,"sessionId":"session-own","result":{}}),
            json!({"id":4,"sessionId":"session-own","result":{}}),
            json!({"id":5,"sessionId":"session-own","result":{}}),
            json!({"method":"Page.loadEventFired","sessionId":"session-own","params":{}}),
        ];
        let mut driver = driver(frames);
        let mut tracker = Tracker::default();
        tracker.token("navigation_started");
        let mut clock = FakeClock::new();
        driver
            .navigate_for_test(
                "route-own",
                "https://requested.example/",
                NavigationWait::Settle,
                10,
                &mut tracker,
                &mut clock,
            )
            .unwrap();

        assert!(!tracker.settled);
        assert_eq!(tracker.lifecycle, ["navigation_started", "load"]);
    }

    #[test]
    fn route_page_is_created_as_a_background_target() {
        let frames = [
            json!({"id":1,"result":{"targetId":"target-own"}}),
            json!({"id":2,"result":{"sessionId":"session-own"}}),
            json!({"id":3,"sessionId":"session-own","result":{}}),
            json!({"id":4,"sessionId":"session-own","result":{}}),
            json!({"id":5,"sessionId":"session-own","result":{}}),
        ];
        let mut driver = driver(frames);
        let mut tracker = Tracker::default();
        driver
            .navigate_for_test(
                "route-own",
                "https://requested.example/",
                NavigationWait::None,
                100,
                &mut tracker,
                &mut FakeClock::new(),
            )
            .unwrap();

        // A foreground target steals focus from the user's frontmost app;
        // the page must be created in the background.
        let create = driver
            .pipe
            .writes
            .iter()
            .find(|write| write["method"] == "Target.createTarget")
            .expect("a Target.createTarget command");
        assert_eq!(create["params"]["url"], "about:blank");
        assert_eq!(create["params"]["background"], true);
    }

    #[test]
    fn present_sends_page_bring_to_front_then_target_activate() {
        let frames = [
            json!({"id":1,"sessionId":"session-own","result":{}}),
            json!({"id":2,"result":{}}),
        ];
        let mut driver = attached_driver(frames);
        driver.present("route-own", 100).unwrap();
        assert_eq!(
            driver
                .pipe
                .writes
                .iter()
                .map(|command| command["method"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["Page.bringToFront", "Target.activateTarget"]
        );
        assert_eq!(driver.pipe.writes[0]["sessionId"], "session-own");
        assert!(driver.pipe.writes[1].get("sessionId").is_none());
        assert_eq!(driver.pipe.writes[1]["params"]["targetId"], "target-own");
    }

    #[test]
    fn cookie_values_never_leave_the_driver() {
        const SECRET: &str = "SECRET-9f1c";
        let frames = [json!({
            "id":1,
            "sessionId":"session-own",
            "result":{
                "cookies":[{
                    "name":"session",
                    "value":SECRET,
                    "domain":"login.example",
                    "path":"/",
                }]
            }
        })];
        let mut driver = attached_driver(frames);
        let names: BTreeSet<String> = driver
            .cookie_names_for_origin("route-own", "https://login.example", 100)
            .unwrap();
        assert_eq!(names, BTreeSet::from(["session".to_string()]));
        assert!(!format!("{names:?}").contains(SECRET));
        assert!(
            !driver
                .pipe
                .writes
                .iter()
                .any(|command| command.to_string().contains(SECRET)),
            "a cookie value escaped into a driver command"
        );
    }
}
