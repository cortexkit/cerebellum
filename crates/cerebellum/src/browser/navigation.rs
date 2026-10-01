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
use crate::browser::state_text::{self, NodeFacts};
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

/// How long a session-verification tab must stay loaded, with no further
/// main-frame commit, before where it ended is read.
///
/// A server that refuses an expired session redirects before the load event,
/// but a single-page app often loads first and then sends an unauthenticated
/// visitor to its sign-in route from script, after asking its own API who is
/// signed in. That API round trip is typically a few hundred milliseconds, so
/// 1.5 s after the load event catches it without making every verification
/// slow.
const VERIFICATION_SETTLE: Duration = Duration::from_millis(1_500);

/// The bound on closing a session-verification tab, separate from the load's
/// own deadline so a load that ran out of time still gets its tab closed.
const VERIFICATION_CLOSE_DEADLINE: Duration = Duration::from_secs(2);

/// Matches what [`NonTypeClassificationRecord::is_credential_field`] counts as
/// a credential field: password inputs, and any element carrying one of the
/// three credential autocomplete tokens.
const CREDENTIAL_FIELD_SELECTOR: &str = "input[type=\"password\" i], [autocomplete~=\"current-password\" i], [autocomplete~=\"new-password\" i], [autocomplete~=\"one-time-code\" i]";

/// How many credential-field matches a verification checks for a rendered
/// box before giving up and counting the page as having none visible.
const MAX_CREDENTIAL_FIELD_CANDIDATES: usize = 16;

use cerebellum_core::vision::max_vision_width_px;
/// Standard-tier vision long-edge cap, in pixels.
///
// The vision limits are shared with the computer plane's window image, so
// both planes size an image for the same readers with the same arithmetic.
pub use cerebellum_core::vision::VISION_LONG_EDGE_PX;
#[cfg(test)]
use cerebellum_core::vision::{VISION_PATCH_PX, VISION_TOKEN_CAP};

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
    /// What the page text prints beside an element's role and name (its
    /// states, a link's URL, whether a field holds a credential), keyed by
    /// ref. Empty for an observation that carries none.
    pub facts: HashMap<String, NodeFacts>,
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

/// Build the committed document from `Page.getNavigationHistory` and
/// `Page.getFrameTree` results, or `None` when either lacks a field it needs.
///
/// The URL comes from the history's current entry rather than the frame
/// tree's frame, because a history entry exists only once its navigation has
/// committed. An error page keeps the URL that failed, which authorizes
/// against the site that was attempted.
pub fn committed_document_from(
    history: &Map<String, Value>,
    frame_tree: &Map<String, Value>,
) -> Option<crate::snapshot_store::CommittedDocument> {
    let current_index = usize::try_from(history.get("currentIndex")?.as_u64()?).ok()?;
    let entries = history.get("entries")?.as_array()?;
    let ids = entries
        .iter()
        .map(|entry| entry.get("id").and_then(Value::as_i64))
        .collect::<Option<Vec<_>>>()?;
    let current = entries.get(current_index)?;
    let url = current.get("url")?.as_str()?.to_string();
    let loader_id = frame_tree
        .get("frameTree")?
        .get("frame")?
        .get("loaderId")?
        .as_str()
        .filter(|loader| !loader.is_empty())?
        .to_string();
    Some(crate::snapshot_store::CommittedDocument {
        url,
        entry_id: ids[current_index],
        history: ids,
        current_index,
        loader_id,
    })
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
    /// Printable states from the node's `properties`, in [`AX_STATES`] order.
    states: Vec<String>,
    /// A link's absolute URL, from its `url` property.
    url: Option<String>,
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

/// What a session-verification tab has shown so far, fed from the events of
/// its own CDP session only.
#[derive(Debug, Clone, PartialEq, Eq)]
struct VerificationLoad {
    target_id: String,
    session_id: String,
    /// Whether the main frame has committed a document other than the blank
    /// page the tab opens on. A load event before that is the blank page's.
    committed: bool,
    /// When the main frame's load event fired after its latest commit.
    loaded_at: Option<Instant>,
    /// The HTTP status of the latest main-frame document response. Redirect
    /// hops do not produce one, so this is the status of where it ended.
    status: Option<u16>,
}

impl VerificationLoad {
    fn observe(&mut self, event: &CdpEvent, observed_at: Instant) {
        match event.method.as_str() {
            "Page.frameNavigated" => {
                let Some(frame) = event
                    .params
                    .as_ref()
                    .and_then(|params| params.get("frame"))
                    .and_then(Value::as_object)
                    .filter(|frame| !frame.contains_key("parentId"))
                else {
                    return;
                };
                if frame
                    .get("url")
                    .and_then(Value::as_str)
                    .is_some_and(|url| !url.starts_with("about:"))
                {
                    self.committed = true;
                }
                // A new main-frame document has not loaded yet, whatever the
                // one before it did; a script redirect lands here.
                self.loaded_at = None;
            }
            "Page.loadEventFired" if self.committed => self.loaded_at = Some(observed_at),
            "Network.responseReceived" => {
                let Some(params) = event.params.as_ref() else {
                    return;
                };
                if params.get("type").and_then(Value::as_str) != Some("Document")
                    || params.get("frameId").and_then(Value::as_str)
                        != Some(self.target_id.as_str())
                {
                    return;
                }
                if let Some(status) = params
                    .get("response")
                    .and_then(|response| response.get("status"))
                    .and_then(Value::as_u64)
                    .and_then(|status| u16::try_from(status).ok())
                {
                    self.status = Some(status);
                }
            }
            _ => {}
        }
    }

    fn settled(&self, now: Instant) -> bool {
        self.committed
            && self
                .loaded_at
                .is_some_and(|loaded| now.saturating_duration_since(loaded) >= VERIFICATION_SETTLE)
    }
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
    /// What the session-verification tab currently open has shown, while a
    /// [`Self::load_in_background_tab`] call is running.
    verification: Option<VerificationLoad>,
    /// A session-verification tab whose close was not confirmed. The next
    /// verification closes it before opening another, so there is never more
    /// than one.
    unclosed_verification_target: Option<String>,
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
            verification: None,
            unclosed_verification_target: None,
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

    /// Load `url` in a new background tab, report where it ended, and close
    /// the tab. `browser.capture_login` uses this to check a session works
    /// the way its holder will use it before capturing it.
    ///
    /// The tab is opened with `background: true`, so the person keeps their
    /// own tab in front and in focus, and it shares the browser's cookie jar,
    /// so the request carries exactly the cookies a capture would read. Only
    /// the `Page`, `Network` and `DOM` domains are enabled, and only on the new
    /// tab's own session: nothing is sent to the person's page, and `Runtime`
    /// is never enabled, so the page cannot observe an automation client
    /// through it. No cookie value is read.
    pub fn load_in_background_tab(
        &mut self,
        url: &str,
        deadline_ms: u64,
    ) -> Result<crate::login_capture::SessionProbe, NavigationDriveError> {
        let mut clock = SystemNavigationClock;
        self.load_in_background_tab_with_clock(url, deadline_ms, &mut clock)
    }

    pub fn main_frame_url(
        &mut self,
        context_key: &str,
        deadline_ms: u64,
    ) -> Result<String, NavigationDriveError> {
        let mut clock = SystemNavigationClock;
        self.main_frame_url_with_clock(context_key, deadline_ms, &mut clock)
    }

    pub fn committed_document(
        &mut self,
        context_key: &str,
        deadline_ms: u64,
    ) -> Result<crate::snapshot_store::CommittedDocument, NavigationDriveError> {
        let mut clock = SystemNavigationClock;
        self.committed_document_with_clock(context_key, deadline_ms, &mut clock)
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

    /// Observe the live target under a pixel before the caller authorizes input.
    pub fn classify_point(
        &mut self,
        context_key: &str,
        position: BrowserClickPosition,
        document_epoch: u64,
        document_url: &str,
        deadline_ms: u64,
    ) -> Result<Result<NonTypeClassificationRecord, ClassificationUnavailable>, NavigationDriveError>
    {
        let mut clock = SystemNavigationClock;
        let deadline = clock
            .now()
            .checked_add(Duration::from_millis(deadline_ms))
            .ok_or(NavigationDriveError::CdpFailure)?;
        self.classify_point_before(
            context_key,
            position,
            document_epoch,
            document_url,
            deadline,
            &mut clock,
        )
    }

    fn classify_point_before<C: NavigationClock>(
        &mut self,
        context_key: &str,
        position: BrowserClickPosition,
        document_epoch: u64,
        document_url: &str,
        deadline: Instant,
        clock: &mut C,
    ) -> Result<Result<NonTypeClassificationRecord, ClassificationUnavailable>, NavigationDriveError>
    {
        self.ensure_attached(context_key, deadline, clock)?;
        let attachment = self
            .attachment
            .clone()
            .ok_or(NavigationDriveError::CdpFailure)?;
        let mut params = Map::new();
        params.insert(
            "x".into(),
            Value::from(
                hit_test_coordinate(position.x_css)
                    .map_err(|_| NavigationDriveError::CdpFailure)?,
            ),
        );
        params.insert(
            "y".into(),
            Value::from(
                hit_test_coordinate(position.y_css)
                    .map_err(|_| NavigationDriveError::CdpFailure)?,
            ),
        );
        params.insert("includeUserAgentShadowDOM".into(), Value::Bool(true));
        let response = self.command_response(
            "DOM.getNodeForLocation",
            Some(params),
            Some(attachment.session_id.clone()),
            deadline,
            None,
            None,
            clock,
        )?;
        let Some(result) = response.result.filter(|_| response.error.is_none()) else {
            return Ok(Err(ClassificationUnavailable::DomReadFailed));
        };
        let Some(backend_node_id) = result
            .get("backendNodeId")
            .and_then(Value::as_u64)
            .filter(|id| *id > 0)
        else {
            return Ok(Err(ClassificationUnavailable::DomReadFailed));
        };
        let Some(frame_id) = result.get("frameId").and_then(Value::as_str) else {
            return Ok(Err(ClassificationUnavailable::DomReadFailed));
        };
        let identity = BackendNodeIdentity {
            target_id: attachment.target_id,
            frame_id: frame_id.to_string(),
            backend_node_id,
        };
        self.classify_click_before(
            context_key,
            &identity,
            document_epoch,
            document_url,
            deadline,
            clock,
        )
    }

    /// Re-hit-test immediately before dispatch so a moved overlay cannot inherit authorization.
    #[allow(clippy::too_many_arguments)]
    pub fn click_point_classified(
        &mut self,
        context_key: &str,
        position: BrowserClickPosition,
        document_epoch: u64,
        document_url: &str,
        expected: &NonTypeClassificationRecord,
        deadline_ms: u64,
        input_dispatched: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        let actual = self
            .classify_point(
                context_key,
                position,
                document_epoch,
                document_url,
                deadline_ms,
            )
            .map_err(ClickDriveError::Navigation)?;
        if actual.as_ref().ok() != Some(expected) {
            return Err(ClickDriveError::ClassificationChanged);
        }
        self.click_point(context_key, position, deadline_ms, input_dispatched)
            .map_err(|error| match error {
                ClickPointDriveError::Navigation(error) => ClickDriveError::Navigation(error),
                ClickPointDriveError::OutsideViewport(refusal) => {
                    ClickDriveError::OutsideViewportAfterScroll(refusal)
                }
            })
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
    /// classified, so callers can refuse without claiming that credential or
    /// payment fields were observed.
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

        // Geometry follows the activated element, not an AX text node with no box.
        let activated = if let Some(record) = revalidation
            .and_then(|(_, _, record)| record)
            .filter(|record| record.node_identity != record.activation_target_identity)
        {
            let nodes = self
                .flattened_dom_nodes_before(&attachment, deadline, clock)
                .map_err(ClickDriveError::Navigation)?
                .map_err(|_| ClickDriveError::ClassificationChanged)?;
            let node = nodes
                .iter()
                .find(|node| {
                    NodeIdentityInput::new(
                        &identity.target_id,
                        &identity.frame_id,
                        node.backend_node_id,
                    )
                    .identity()
                    .ok()
                    .as_ref()
                        == Some(&record.activation_target_identity)
                })
                .ok_or(ClickDriveError::ClassificationChanged)?;
            Some(BackendNodeIdentity {
                backend_node_id: node.backend_node_id,
                ..identity.clone()
            })
        } else {
            None
        };
        let requested_identity = identity;
        let identity = activated.as_ref().unwrap_or(identity);

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
                let mut params = Map::new();
                params.insert("backendNodeId".into(), Value::from(hit_backend_node_id));
                params.insert("fetchRelatives".into(), Value::Bool(false));
                let ax = self
                    .command_response(
                        "Accessibility.getPartialAXTree",
                        Some(params),
                        Some(attachment.session_id.clone()),
                        deadline,
                        None,
                        None,
                        clock,
                    )
                    .ok()
                    .and_then(|response| response.result);
                let node = ax
                    .as_ref()
                    .and_then(|result| result.get("nodes"))
                    .and_then(Value::as_array)
                    .and_then(|nodes| nodes.first());
                return Err(ClickDriveError::Intercepted(serde_json::json!({
                    "hit_backend_node_id":hit_backend_node_id,
                    "hit_role":node.and_then(|node| node.pointer("/role/value")),
                    "hit_name":node.and_then(|node| node.pointer("/name/value")),
                    "hit_inside_target":false,
                })));
            }
        }

        if let Some((document_epoch, current_origin, expected)) = revalidation {
            let actual = self
                .classify_click_before(
                    context_key,
                    requested_identity,
                    document_epoch,
                    current_origin,
                    deadline,
                    clock,
                )
                .map_err(ClickDriveError::Navigation)?;
            // Authorization binds the complete original record, including its
            // source node and activated ancestor, rather than just its severity.
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

        let snapshot_dom = if classification_context.is_some() || mode == SnapshotKind::Actionable {
            Some(
                self.flattened_dom_nodes_before(&attachment, deadline, clock)
                    .unwrap_or(Err(ClassificationUnavailable::DomReadFailed)),
            )
        } else {
            None
        };
        if let Some((document_epoch, document_url)) = classification_context {
            // One DOM read serves every ref. A failure here leaves each ref
            // with the same named reason rather than failing the snapshot:
            // the refs are still observable, only their form facts are not.
            let projection = document_origin(document_url).and_then(|origin| {
                snapshot_dom
                    .as_ref()
                    .expect("classification requested DOM")
                    .as_ref()
                    .map(|nodes| (origin, nodes))
                    .map_err(Clone::clone)
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

        if mode == SnapshotKind::Actionable {
            // Without the DOM the page text still prints every element; it
            // only loses field values and placeholders, which stay withheld.
            if let Some(nodes) = snapshot_dom
                .as_ref()
                .and_then(|result| result.as_ref().ok())
            {
                collect_dom_facts(
                    &mut observation,
                    nodes,
                    classification_context.map(|(_, url)| url),
                );
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

    fn load_in_background_tab_with_clock<C: NavigationClock>(
        &mut self,
        url: &str,
        deadline_ms: u64,
        clock: &mut C,
    ) -> Result<crate::login_capture::SessionProbe, NavigationDriveError> {
        let deadline = clock
            .now()
            .checked_add(Duration::from_millis(deadline_ms))
            .ok_or(NavigationDriveError::CdpFailure)?;
        if let Some(target_id) = self.unclosed_verification_target.clone() {
            self.close_verification_target(&target_id, clock)?;
        }
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
        // The new tab is remembered before anything else can fail, so it is
        // closed below or, if that close fails, before the next verification
        // opens another.
        self.unclosed_verification_target = Some(target_id.clone());
        let probe = self.load_in_verification_target(&target_id, url, deadline, clock);
        self.verification = None;
        // A close that fails leaves the tab recorded; the next verification
        // refuses to open another until it is gone. What this load saw stands.
        let _ = self.close_verification_target(&target_id, clock);
        probe
    }

    fn load_in_verification_target<C: NavigationClock>(
        &mut self,
        target_id: &str,
        url: &str,
        deadline: Instant,
        clock: &mut C,
    ) -> Result<crate::login_capture::SessionProbe, NavigationDriveError> {
        let mut attach_params = Map::new();
        attach_params.insert("targetId".into(), Value::String(target_id.to_string()));
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
        self.verification = Some(VerificationLoad {
            target_id: target_id.to_string(),
            session_id: session_id.clone(),
            committed: false,
            loaded_at: None,
            status: None,
        });
        for domain in ["Page.enable", "Network.enable"] {
            self.command(
                domain,
                None,
                Some(session_id.clone()),
                deadline,
                None,
                clock,
            )?;
        }
        let mut params = Map::new();
        params.insert("url".into(), Value::String(url.to_string()));
        let navigated = self.command(
            "Page.navigate",
            Some(params),
            Some(session_id.clone()),
            deadline,
            None,
            clock,
        )?;
        if let Some(error_text) = navigated
            .get("errorText")
            .and_then(Value::as_str)
            .filter(|error_text| !error_text.is_empty())
        {
            return Err(NavigationDriveError::NavigationFailed {
                error_text: error_text.to_string(),
            });
        }
        loop {
            if self
                .verification
                .as_ref()
                .is_some_and(|load| load.settled(clock.now()))
            {
                break;
            }
            // A page that never finishes loading is not shown to work.
            if clock.now() >= deadline {
                return Err(NavigationDriveError::CdpFailure);
            }
            self.read_turn(None, None, clock.now())?;
            let remaining = deadline.saturating_duration_since(clock.now());
            clock.sleep(cmp::min(POLL_INTERVAL, remaining));
        }
        let status = self.verification.as_ref().and_then(|load| load.status);
        let history = self.command(
            "Page.getNavigationHistory",
            None,
            Some(session_id.clone()),
            deadline,
            None,
            clock,
        )?;
        let final_url = current_history_url(&history).ok_or(NavigationDriveError::CdpFailure)?;
        let credential_field = self.visible_credential_field(&session_id, deadline, clock)?;
        Ok(crate::login_capture::SessionProbe {
            final_url,
            status,
            credential_field,
        })
    }

    /// Whether the verification tab's page shows a credential field. A match
    /// with no rendered box (`display: none`, a detached template) is not
    /// shown to anyone, so it does not make a signed-in page a sign-in page.
    fn visible_credential_field<C: NavigationClock>(
        &mut self,
        session_id: &str,
        deadline: Instant,
        clock: &mut C,
    ) -> Result<bool, NavigationDriveError> {
        let mut params = Map::new();
        params.insert("depth".into(), Value::from(0));
        let document = self.command(
            "DOM.getDocument",
            Some(params),
            Some(session_id.to_string()),
            deadline,
            None,
            clock,
        )?;
        let root = document
            .get("root")
            .and_then(|root| root.get("nodeId"))
            .and_then(Value::as_u64)
            .ok_or(NavigationDriveError::CdpFailure)?;
        let mut params = Map::new();
        params.insert("nodeId".into(), Value::from(root));
        params.insert(
            "selector".into(),
            Value::String(CREDENTIAL_FIELD_SELECTOR.to_string()),
        );
        let matched = self.command(
            "DOM.querySelectorAll",
            Some(params),
            Some(session_id.to_string()),
            deadline,
            None,
            clock,
        )?;
        let node_ids = matched
            .get("nodeIds")
            .and_then(Value::as_array)
            .ok_or(NavigationDriveError::CdpFailure)?
            .iter()
            .filter_map(Value::as_u64)
            .take(MAX_CREDENTIAL_FIELD_CANDIDATES)
            .collect::<Vec<_>>();
        for node_id in node_ids {
            let mut params = Map::new();
            params.insert("nodeId".into(), Value::from(node_id));
            // Chrome answers an element with no layout box with an error, so
            // an error here means "not rendered" rather than a failed read.
            let boxed = self.command_response(
                "DOM.getBoxModel",
                Some(params),
                Some(session_id.to_string()),
                deadline,
                None,
                None,
                clock,
            )?;
            let rendered = boxed
                .result
                .as_ref()
                .and_then(|result| result.get("model"))
                .is_some_and(|model| {
                    let positive = |key: &str| {
                        model
                            .get(key)
                            .and_then(Value::as_f64)
                            .is_some_and(|value| value > 0.0)
                    };
                    positive("width") && positive("height")
                });
            if rendered {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Close a session-verification tab, and forget it once it is gone. A
    /// close Chrome refuses because the tab no longer exists (the person
    /// closed it) also counts as gone.
    fn close_verification_target<C: NavigationClock>(
        &mut self,
        target_id: &str,
        clock: &mut C,
    ) -> Result<(), NavigationDriveError> {
        let deadline = clock
            .now()
            .checked_add(VERIFICATION_CLOSE_DEADLINE)
            .ok_or(NavigationDriveError::CdpFailure)?;
        let mut params = Map::new();
        params.insert("targetId".into(), Value::String(target_id.to_string()));
        let closed = self.command_response(
            "Target.closeTarget",
            Some(params.clone()),
            None,
            deadline,
            None,
            None,
            clock,
        )?;
        let gone = closed.error.is_none() || {
            let still_there = self.command_response(
                "Target.getTargetInfo",
                Some(params),
                None,
                deadline,
                None,
                None,
                clock,
            )?;
            still_there.error.is_some()
        };
        if !gone {
            return Err(NavigationDriveError::CdpFailure);
        }
        if self.unclosed_verification_target.as_deref() == Some(target_id) {
            self.unclosed_verification_target = None;
        }
        Ok(())
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

    /// Every part is required: a document whose history entry or loader
    /// cannot be named cannot be shown to be the one a grant or a snapshot
    /// covered, so a missing field is a CDP failure rather than a default.
    fn committed_document_with_clock<C: NavigationClock>(
        &mut self,
        context_key: &str,
        deadline_ms: u64,
        clock: &mut C,
    ) -> Result<crate::snapshot_store::CommittedDocument, NavigationDriveError> {
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
            Some(attachment.session_id.clone()),
            deadline,
            None,
            clock,
        )?;
        let tree = self.command(
            "Page.getFrameTree",
            None,
            Some(attachment.session_id),
            deadline,
            None,
            clock,
        )?;
        committed_document_from(&history, &tree).ok_or(NavigationDriveError::CdpFailure)
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
            // The transport's own parser, so a frame is read here exactly as
            // the transport reads it below; it accepts the unpaired
            // surrogates Chrome sends for page text that serde_json alone
            // refuses.
            let value = crate::cdp::parse_json_message(&frame)
                .map_err(|_| NavigationDriveError::CdpFailure)?;
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
            // Events from the session-verification tab update only that tab's
            // load record; they are never applied to the person's page or to a
            // navigation's tracker.
            if let Some(load) = self.verification.as_mut() {
                if event.session_id.as_deref() == Some(load.session_id.as_str()) {
                    load.observe(&event, observed_at);
                    continue;
                }
            }
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
                if let Some(params) = event.params.as_ref() {
                    if let Some(id) = params.get("requestId").and_then(Value::as_str) {
                        tracker.network_request_started(
                            id,
                            params.get("type").and_then(Value::as_str).unwrap_or(""),
                            observed_at,
                        );
                    } else if !is_redirect_continuation {
                        tracker.request_started();
                    }
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
            "Network.loadingFinished" | "Network.loadingFailed" => {
                if let Some(id) = event
                    .params
                    .as_ref()
                    .and_then(|params| params.get("requestId"))
                    .and_then(Value::as_str)
                {
                    tracker.network_request_finished(id, observed_at);
                } else {
                    tracker.request_finished(observed_at);
                }
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
                if let Some(id) = params.get("requestId").and_then(Value::as_str) {
                    tracker.network_request_type(
                        id,
                        params.get("type").and_then(Value::as_str).unwrap_or(""),
                        observed_at,
                    );
                }
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

/// The URL of the current entry in a `Page.getNavigationHistory` result.
fn current_history_url(history: &Map<String, Value>) -> Option<String> {
    let current_index = usize::try_from(history.get("currentIndex")?.as_u64()?).ok()?;
    history
        .get("entries")?
        .as_array()?
        .get(current_index)?
        .get("url")?
        .as_str()
        .map(str::to_string)
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
        let node_type = object
            .get("nodeType")
            .and_then(Value::as_u64)
            .ok_or(field_invalid("nodeType"))?;
        if !matches!(node_type, 1 | 3) {
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
        // Text nodes carry backend identities in AX snapshots but have no attributes.
        // Retain them so their parent chain can identify the activated element.
        let empty_attributes = Vec::new();
        let attribute_values = if node_type == 3 {
            &empty_attributes
        } else {
            object
                .get("attributes")
                .and_then(Value::as_array)
                .ok_or(ClassificationUnavailable::AttributesMissing { node_id })?
        };
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
        if node.attributes.get("role").is_some_and(|role| {
            matches!(
                role.as_str(),
                "button" | "link" | "checkbox" | "radio" | "switch" | "tab" | "menuitem" | "option"
            )
        }) || matches!(node.local_name.as_str(), "select" | "textarea" | "summary")
        {
            element = element.built_in_activation(true);
        }
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
        let declared = declared.trim();
        if declared.starts_with("//") {
            return self
                .current_origin
                .split_once(":")
                .map(|(scheme, _)| format!("{scheme}:{declared}"));
        }
        if declared
            .split(['/', '?', '#'])
            .next()
            .is_some_and(|part| part.contains(':'))
        {
            return Some(declared.to_string());
        }
        // Relative paths and fragments keep the document origin. Only the origin
        // is used for authorization; the browser resolves the full landing path.
        let base = self
            .nodes
            .iter()
            .find(|node| node.local_name == "base" && node.attributes.contains_key("href"))
            .and_then(|node| node.attributes.get("href"));
        let base_origin = match base {
            Some(base) if base.starts_with("//") => {
                self.current_origin.split_once(':').and_then(|(scheme, _)| {
                    classification::canonical_origin_from_url(&format!("{scheme}:{base}"))
                })
            }
            Some(base) if base.contains(':') => classification::canonical_origin_from_url(base),
            _ => classification::canonical_origin(self.current_origin),
        };
        base_origin.map(|origin| format!("{origin}/{}", declared.trim_start_matches('/')))
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
        let (states, url) = ax_states_and_url(object.get("properties"));
        Ok(Self {
            node_id,
            ignored,
            role: ax_value_text(object.get("role")).unwrap_or_default(),
            name: ax_value_text(object.get("name")).unwrap_or_default(),
            value: ax_value_text(object.get("value")),
            child_ids,
            backend_node_id,
            frame_id,
            states,
            url,
        })
    }
}

/// The accessibility states the page text prints, in the order it prints
/// them. Others (focusable, settable, live-region settings, relations) describe
/// how the page is built rather than what a reader sees.
const AX_STATES: [&str; 10] = [
    "focused", "disabled", "checked", "pressed", "selected", "expanded", "required",
    "invalid", "readonly", "modal",
];

/// Read the printable states and a link's URL from a node's `properties`.
///
/// Lenient on purpose: a property of a shape this does not know is skipped
/// rather than failing the snapshot, because these only decorate a line and
/// Chrome adds properties over time.
fn ax_states_and_url(properties: Option<&Value>) -> (Vec<String>, Option<String>) {
    let mut found: HashMap<&str, String> = HashMap::new();
    let mut url = None;
    for property in properties.and_then(Value::as_array).into_iter().flatten() {
        let Some(name) = property.get("name").and_then(Value::as_str) else {
            continue;
        };
        let value = property.get("value").and_then(|value| value.get("value"));
        let text = match value {
            Some(Value::Bool(value)) => value.to_string(),
            Some(Value::String(value)) => value.clone(),
            _ => continue,
        };
        if name == "url" {
            url = Some(text).filter(|url| !url.is_empty() && url.len() <= 4_096);
            continue;
        }
        let state = match (name, text.as_str()) {
            ("checked" | "pressed", "mixed") => "mixed".to_string(),
            ("expanded", "false") => "collapsed".to_string(),
            ("invalid", "false") => continue,
            ("invalid", _) => "invalid".to_string(),
            (_, "true") => name.to_string(),
            _ => continue,
        };
        if let Some(known) = AX_STATES.iter().find(|known| **known == name) {
            found.insert(known, state);
        }
    }
    let states = AX_STATES
        .iter()
        .filter_map(|name| found.remove(name))
        .collect();
    (states, url)
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
    let mut facts = HashMap::new();
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
                    if !node.states.is_empty() || node.url.is_some() {
                        facts.insert(
                            ref_name.clone(),
                            NodeFacts {
                                states: node.states.clone(),
                                url: node.url.clone(),
                                ..NodeFacts::default()
                            },
                        );
                    }
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
        facts,
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

/// Whether a form field holds a credential or payment value: a password
/// input, a field whose autocomplete names a username, password, one-time code
/// or card detail, or one whose name or id says so. The page text never prints
/// such a field's value.
fn credential_or_payment_field(node: &RawDomNode) -> bool {
    let input_type = node
        .attributes
        .get("type")
        .map(String::as_str)
        .unwrap_or("text");
    input_type.eq_ignore_ascii_case("password")
        || node.attributes.get("autocomplete").is_some_and(|tokens| {
            tokens.split_ascii_whitespace().any(|token| {
                let token = token.to_ascii_lowercase();
                matches!(
                    token.as_str(),
                    "username" | "current-password" | "new-password" | "one-time-code"
                ) || token.starts_with("cc-")
            })
        })
        || ["name", "id"]
            .iter()
            .filter_map(|key| node.attributes.get(*key))
            .any(|name| {
                let name = name.to_ascii_lowercase();
                [
                    "password", "passwd", "secret", "token", "card", "cvv", "cvc", "iban",
                ]
                .iter()
                .any(|token| name.contains(token))
            })
}

/// Add what only the DOM knows to each ref's facts: whether a field is a
/// credential or payment field, its placeholder, and a link's target when
/// Chrome did not report one.
///
/// Every element whose DOM node is found gets a credential verdict, so the
/// page text can print a field's value only when the verdict is "no"; an
/// element the DOM read missed keeps none and its value stays withheld.
fn collect_dom_facts(
    observation: &mut BrowserSnapshotObservation,
    nodes: &[RawDomNode],
    page_url: Option<&str>,
) {
    let by_backend: HashMap<_, _> = nodes
        .iter()
        .map(|node| (node.backend_node_id, node))
        .collect();
    for reference in &observation.refs {
        let Some(node) = reference
            .backend_identity
            .as_ref()
            .and_then(|identity| by_backend.get(&identity.backend_node_id))
        else {
            continue;
        };
        let facts = observation
            .facts
            .entry(reference.captured.reference.clone())
            .or_default();
        facts.credential = Some(credential_or_payment_field(node));
        facts.placeholder = node
            .attributes
            .get("placeholder")
            .filter(|placeholder| !placeholder.trim().is_empty())
            .map(|placeholder| truncate_ax_field(placeholder, MAX_NAME_BYTES));
        if facts.url.is_none() && matches!(node.local_name.as_str(), "a" | "area") {
            if let (Some(href), Some(page_url)) = (node.attributes.get("href"), page_url) {
                facts.url = Some(truncate_ax_field(
                    &state_text::resolve_href(href, page_url),
                    MAX_NAME_BYTES,
                ));
            }
        }
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
        // A snapshot keeps only the refs its text names, so the text lists
        // every ref handed in.
        let records: Vec<AxRecord> = refs
            .iter()
            .map(|record| AxRecord {
                depth: 0,
                role: record.captured.role.clone(),
                name: record.captured.name.clone(),
                value: None,
                reference: Some(record.captured.reference.clone()),
            })
            .collect();
        let retained = plane
            .retain_text_snapshot(&route, SnapshotKind::Ax, &records, None, refs, 4096, None)
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
            assert_eq!(
                reply["outcome"], "classification_unavailable",
                "{code}: {reply}"
            );
            assert!(reply["detail"].get("required").is_none());
            assert!(reply["detail"].get("missing_hazard").is_none());
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
                Severity::new(if element_id == "plain" { 2 } else { 1 }, false, false),
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

        // Raising severity does not grant access to the landing origin.
        let reply = click_reply(
            refs,
            json!({"tier": 2, "credential": false, "financial": false}),
        )
        .await;
        assert_eq!(reply["outcome"], "authorization_denied", "{reply}");

        // Missing facts refuse without inventing credential or payment hazards.
        let refs = snapshot_refs(vec![], Some((7, "about:blank")));
        let reply = click_reply(refs, below_floor).await;
        assert_eq!(reply["outcome"], "classification_unavailable");
        assert!(reply["detail"].get("required").is_none());
        assert_eq!(
            reply["detail"]["classification_unavailable"], "document_origin_unavailable",
            "{reply}"
        );
    }

    #[tokio::test]
    async fn a_point_click_requires_live_observation_before_computing_severity() {
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
                None,
            )
            .await
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
        assert_eq!(reply["outcome"], "no_session", "{reply}");
        assert!(reply["detail"].get("required").is_none());
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

    fn github_link_document() -> Value {
        json!({"nodes":[
            flattened_dom_node(1, None, 10, "html", &[]),
            flattened_dom_node(2, Some(1), 42, "a", &["href", "/organizations/cortexkit/settings/installations/123", "class", "btn"]),
            flattened_dom_node(3, Some(2), 43, "span", &[]),
            {"nodeId":4,"parentId":3,"backendNodeId":44,"nodeType":3,"nodeName":"#text","localName":"","nodeValue":"Configure"}
        ]})
    }

    fn github_record(backend: u64) -> NonTypeClassificationRecord {
        classify_flattened_document(
            github_link_document().as_object().unwrap(),
            &BackendNodeIdentity::new("target-own", "frame-main", backend).unwrap(),
            7,
            "https://github.com/organizations/cortexkit/settings/installations",
        )
        .unwrap()
    }

    fn assert_navigation_authorized(record: &NonTypeClassificationRecord) {
        use crate::authorization::{
            Action, ActionGrant, AuthorizationRequest, GrantStore, Severity,
        };
        assert_eq!(record.required_tier, 1);
        assert!(!record.credential && !record.financial && !record.activation_invokes_form_submit);
        assert!(
            crate::authorization::target_hazards(Action::Click, Some(record))
                .unwrap()
                .is_empty()
        );
        let grant = ActionGrant::new(
            "navigation",
            1,
            "route-own",
            Severity::new(1, false, false),
            ["https://github.com".to_string()],
        );
        let store = GrantStore::try_new([grant]).unwrap();
        store
            .authorize(
                AuthorizationRequest::click(
                    "route-own",
                    Severity::new(1, false, false),
                    "snapshot",
                    "binding",
                    record,
                ),
                "https://github.com",
            )
            .unwrap();
        store
            .authorize(
                AuthorizationRequest::click_point(
                    "route-own",
                    Severity::new(1, false, false),
                    "snapshot",
                    "binding",
                    record,
                ),
                "https://github.com",
            )
            .unwrap();
    }

    fn github_ref_dispatch(backend: u64) {
        let record = github_record(backend);
        assert_navigation_authorized(&record);
        assert_eq!(
            record.activation_target_identity,
            NodeIdentityInput::new("target-own", "frame-main", 42)
                .identity()
                .unwrap()
        );
        let quad = json!({"quads":[[10,20,34,20,34,52,10,52]]});
        let mut results = Vec::new();
        if backend != 42 {
            results.extend([json!({}), github_link_document()]);
        }
        results.extend([
            quad.clone(), json!({}), quad, layout_metrics(0.0, 0.0, 1280.0, 713.0),
            json!({"backendNodeId":44,"frameId":"frame-main"}),
            json!({"node":{"backendNodeId":42,"children":[{"backendNodeId":43,"children":[{"backendNodeId":44}]}]}}),
            json!({}), github_link_document(), json!({}), json!({}), json!({}), json!({})
        ]);
        let mut driver = attached_driver(results.into_iter().enumerate().map(
            |(index, result)| json!({"id":index+1,"sessionId":"session-own","result":result}),
        ));
        let mut events = Vec::new();
        driver
            .click_with_clock(
                "route-own",
                &BackendNodeIdentity::new("target-own", "frame-main", backend).unwrap(),
                1000,
                &mut |event| events.push(event),
                Some((7, "https://github.com", Some(&record))),
                &mut FakeClock::new(),
            )
            .unwrap();
        assert_eq!(events.len(), 2);
        let geometry = driver
            .pipe
            .writes
            .iter()
            .find(|write| write["method"] == "DOM.getContentQuads")
            .unwrap();
        assert_eq!(geometry["params"]["backendNodeId"], 42);
    }

    #[test]
    fn github_link_ref_accepts_descendant_hit_at_navigation_tier() {
        github_ref_dispatch(42);
    }

    #[test]
    fn github_text_ref_activates_link_at_navigation_tier() {
        github_ref_dispatch(44);
    }

    #[test]
    fn github_point_on_text_dispatches_at_navigation_tier() {
        let results = [
            json!({"backendNodeId":44,"frameId":"frame-main"}),
            json!({}),
            github_link_document(),
            layout_metrics(0.0, 0.0, 1280.0, 713.0),
            json!({}),
            json!({}),
            json!({}),
            json!({}),
        ];
        let mut driver = attached_driver(results.into_iter().enumerate().map(
            |(index, result)| json!({"id":index+1,"sessionId":"session-own","result":result}),
        ));
        let record = github_record(44);
        assert_navigation_authorized(&record);
        let mut events = Vec::new();
        driver
            .click_point_classified(
                "route-own",
                BrowserClickPosition {
                    x_css: 22.0,
                    y_css: 36.0,
                },
                7,
                "https://github.com",
                &record,
                1000,
                &mut |event| events.push(event),
            )
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(
            record.activation_target_identity,
            github_record(42).activation_target_identity
        );
    }

    #[test]
    fn github_same_origin_link_is_navigation_not_submit() {
        assert_navigation_authorized(&github_record(42));
    }

    #[test]
    fn password_submit_retains_tier_four_and_credential_hazard() {
        let doc = json!({"nodes":[
            flattened_dom_node(1,None,10,"form",&[]),
            flattened_dom_node(2,Some(1),20,"input",&["type","password"]),
            flattened_dom_node(3,Some(1),42,"button",&["type","submit"])
        ]});
        let record = classify_flattened_document(
            doc.as_object().unwrap(),
            &BackendNodeIdentity::new("target-own", "frame-main", 42).unwrap(),
            7,
            "https://github.com",
        )
        .unwrap();
        assert_eq!(record.required_tier, 4);
        assert!(record.credential && !record.financial);
        assert!(!crate::authorization::target_hazards(
            crate::authorization::Action::Click,
            Some(&record)
        )
        .unwrap()
        .is_empty());
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
            json!({"id":7,"sessionId":"session-own","result":{"nodes":[{"role":{"value":"banner"},"name":{"value":"Sticky header"}}]}}),
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

        assert_eq!(
            result,
            Err(ClickDriveError::Intercepted(
                json!({"hit_backend_node_id":99,"hit_role":"banner","hit_name":"Sticky header","hit_inside_target":false})
            ))
        );
        assert!(input_events.is_empty());
        assert_eq!(driver.pipe.writes[5]["method"], "DOM.describeNode");
        assert!(driver
            .pipe
            .writes
            .iter()
            .all(|write| write["method"] != "Input.dispatchMouseEvent"));
    }

    /// Turn a recorded page fixture into the CDP replies a real capture of
    /// that page receives, and run the real snapshot over them.
    ///
    /// A fixture is a nested accessibility tree whose nodes may carry a DOM
    /// tag and attributes, a value, and AX properties. Node `i` in document
    /// order gets AX id `n{i}` and backend id `i + 1`; the root is in
    /// `frame-main`. Replies are queued in the order the traversal asks: the
    /// root, then each node's children in document order, then the DOM read.
    fn fixture_observation(fixture: &str) -> (BrowserSnapshotObservation, String) {
        fn flatten(node: &Value, parent: Option<usize>, out: &mut Vec<(Value, Option<usize>, Vec<usize>)>) {
            let index = out.len();
            out.push((node.clone(), parent, Vec::new()));
            for child in node["children"].as_array().into_iter().flatten() {
                let child_index = out.len();
                out[index].2.push(child_index);
                flatten(child, Some(index), out);
            }
        }
        let fixture: Value = serde_json::from_str(fixture).unwrap();
        let url = fixture["url"].as_str().unwrap().to_string();
        let mut nodes = Vec::new();
        flatten(&fixture["tree"], None, &mut nodes);
        let ax = |index: usize| -> Value {
            let (node, _, children) = &nodes[index];
            let mut value = json!({
                "nodeId": format!("n{index}"),
                "ignored": node["ignored"].as_bool().unwrap_or(false),
                "role": {"type": "role", "value": node["role"]},
                "name": {"type": "computedString", "value": node["name"].as_str().unwrap_or("")},
                "childIds": children.iter().map(|child| format!("n{child}")).collect::<Vec<_>>(),
                "backendDOMNodeId": index + 1,
            });
            if index == 0 {
                value["frameId"] = json!("frame-main");
            }
            if let Some(text) = node.get("value") {
                value["value"] = json!({"type": "string", "value": text});
            }
            if let Some(properties) = node["props"].as_object() {
                value["properties"] = properties
                    .iter()
                    .map(|(name, property)| {
                        let kind = if property.is_boolean() { "boolean" } else { "token" };
                        json!({"name": name, "value": {"type": kind, "value": property}})
                    })
                    .collect();
            }
            value
        };
        let mut frames = vec![
            json!({"id":1,"sessionId":"session-own","result":{}}),
            json!({"id":2,"sessionId":"session-own","result":{"node":ax(0)}}),
        ];
        for (_, _, children) in &nodes {
            if !children.is_empty() {
                let id = frames.len() + 1;
                let replies: Vec<Value> = children.iter().map(|child| ax(*child)).collect();
                frames.push(json!({"id":id,"sessionId":"session-own","result":{"nodes":replies}}));
            }
        }
        let dom: Vec<Value> = nodes
            .iter()
            .enumerate()
            .map(|(index, (node, parent, _))| {
                let attributes: Vec<&str> = node["attrs"]
                    .as_object()
                    .into_iter()
                    .flatten()
                    .flat_map(|(name, value)| [name.as_str(), value.as_str().unwrap()])
                    .collect();
                flattened_dom_node(
                    index as u64 + 1,
                    parent.map(|parent| parent as u64 + 1),
                    index as u64 + 1,
                    node["tag"].as_str().unwrap_or("div"),
                    &attributes,
                )
            })
            .collect();
        let id = frames.len() + 1;
        frames.push(json!({"id":id,"sessionId":"session-own","result":{}}));
        frames.push(json!({"id":id + 1,"sessionId":"session-own","result":{"nodes":dom}}));
        let observation = attached_driver(frames)
            .snapshot_with_clock(
                "route-own",
                SnapshotKind::Actionable,
                1000,
                Some((7, &url)),
                &mut FakeClock::new(),
            )
            .unwrap();
        (observation, url)
    }

    const X_LIKE: &str = include_str!("fixtures/x_like_page.json");
    const SETTINGS_LIKE: &str = include_str!("fixtures/settings_like_page.json");

    fn render_fixture(
        observation: &BrowserSnapshotObservation,
        url: &str,
        zoom: Option<&str>,
        max_bytes: usize,
    ) -> state_text::RenderedState {
        state_text::render(&state_text::RenderInput {
            records: &observation.records,
            facts: &observation.facts,
            page_url: url,
            snapshot_id: "0123456789abcdef0123456789abcdef",
            zoom: zoom.map(|reference| state_text::Zoom {
                requested: reference,
                target: Some(reference),
            }),
            max_bytes,
        })
    }

    /// The ref of the first record with `role` (and `name`, when given).
    fn ref_of(observation: &BrowserSnapshotObservation, role: &str, name: Option<&str>) -> String {
        observation
            .records
            .iter()
            .find(|record| record.role == role && name.is_none_or(|name| record.name == name))
            .and_then(|record| record.reference.clone())
            .unwrap()
    }

    #[test]
    fn x_like_outline_and_zoom_match_their_golden_text() {
        let (observation, url) = fixture_observation(X_LIKE);
        let outline = render_fixture(&observation, &url, None, 65_536).text;
        assert_eq!(outline, include_str!("fixtures/x_like_outline.txt"));
        // The outline of a timeline page stays small...
        assert!(outline.len() < 3 * 1024, "{} bytes", outline.len());
        // ...and one zoom on a post (an article named in the outline) reads it.
        let article = ref_of(&observation, "article", None);
        assert!(outline.contains(&format!("{article} article Pebble Post")));
        let zoomed = render_fixture(&observation, &url, Some(&article), 65_536).text;
        assert_eq!(zoomed, include_str!("fixtures/x_like_zoom_article.txt"));
        assert!(zoomed.contains("text A seed swap with"), "{zoomed}");
        assert!(zoomed.contains("@moss_example, Value: example.com/moss_example"), "{zoomed}");
    }

    #[test]
    fn settings_like_outline_and_zoom_match_their_golden_text() {
        let (observation, url) = fixture_observation(SETTINGS_LIKE);
        let outline = render_fixture(&observation, &url, None, 65_536).text;
        assert_eq!(outline, include_str!("fixtures/settings_like_outline.txt"));
        let form = ref_of(&observation, "form", Some("Change password"));
        let zoomed = render_fixture(&observation, &url, Some(&form), 65_536).text;
        assert_eq!(zoomed, include_str!("fixtures/settings_like_zoom_form.txt"));
    }

    #[test]
    fn a_small_budget_keeps_posts_before_the_sidebar() {
        let (observation, url) = fixture_observation(X_LIKE);
        let outline = render_fixture(&observation, &url, None, 65_536).text;
        // The full outline has both the posts and the sidebar...
        assert!(outline.contains("article Paper Kite Club"), "{outline}");
        assert!(outline.contains("complementary Trending"), "{outline}");
        // ...and the posts are listed before it.
        assert!(outline.find("article Paper Kite") < outline.find("complementary Trending"));

        // A budget that cannot hold both keeps the posts and cuts the
        // sidebar, and the last line says so.
        let cut = render_fixture(&observation, &url, None, 1_200);
        assert!(cut.text.len() <= 1_200, "{}", cut.text);
        assert!(cut.text.contains("article Paper Kite Club"), "{}", cut.text);
        assert!(!cut.text.contains("complementary Trending"), "{}", cut.text);
        assert!(!cut.printed_refs.contains(&ref_of(&observation, "searchbox", None)));
        assert!(
            cut.text.ends_with("complementary e100 (all); zoom one of them or raise max_bytes]\n"),
            "{}",
            cut.text
        );

        // The whole page zoomed is in document order, navigation first, yet a
        // cut still spends the budget on the posts and drops the chrome.
        let root = ref_of(&observation, "RootWebArea", None);
        let page = render_fixture(&observation, &url, Some(&root), 3_000);
        assert!(page.text.len() <= 3_000, "{}", page.text);
        assert!(page.text.contains("text A seed swap with"), "{}", page.text);
        assert!(page.text.contains("Curious about balcony gardening?"), "{}", page.text);
        assert!(!page.text.contains("Who to follow"), "{}", page.text);
        assert!(!page.text.contains("link Explore"), "{}", page.text);
        assert!(page.text.contains("banner e3 (all)"), "{}", page.text);
    }

    #[test]
    fn every_actionable_ref_appears_in_a_full_zoom() {
        for fixture in [X_LIKE, SETTINGS_LIKE] {
            let (observation, url) = fixture_observation(fixture);
            let root = ref_of(&observation, "RootWebArea", None);
            let page = render_fixture(&observation, &url, Some(&root), 262_144);
            let actionable: Vec<&str> = observation
                .records
                .iter()
                .filter(|record| {
                    matches!(
                        record.role.as_str(),
                        "link" | "button" | "textbox" | "searchbox" | "combobox" | "checkbox"
                            | "tab" | "MenuListOption"
                    )
                })
                .filter_map(|record| record.reference.as_deref())
                .collect();
            assert!(actionable.len() > 10, "{actionable:?}");
            for reference in actionable {
                assert!(
                    page.printed_refs.contains(reference)
                        && page.text.lines().any(|line| line.trim_start().starts_with(&format!("{reference} "))),
                    "{reference} missing from\n{}",
                    page.text
                );
            }
        }
    }

    #[test]
    fn credential_and_payment_values_never_print() {
        let (observation, url) = fixture_observation(SETTINGS_LIKE);
        let root = ref_of(&observation, "RootWebArea", None);
        let old_password = ref_of(&observation, "textbox", Some("Old password"));
        // Chrome's inner editor holds the password again as text; a zoom on
        // it shows the field instead.
        let inner_text = ref_of(&observation, "StaticText", Some("hunter2-planted"));
        let texts = [
            render_fixture(&observation, &url, None, 65_536).text,
            render_fixture(&observation, &url, Some(&root), 65_536).text,
            render_fixture(&observation, &url, Some(&old_password), 65_536).text,
            render_fixture(&observation, &url, Some(&inner_text), 65_536).text,
        ];
        for text in &texts {
            for secret in ["hunter2-planted", "s3cret-new-value", "octocat-private", "4111111111111111"] {
                assert!(!text.contains(secret), "{secret} printed in\n{text}");
            }
        }
        // Values do print where the field is ordinary, so the checks above
        // are not passing for want of any value at all.
        assert!(texts[1].contains("textbox Backup email, Value: octo@example.com"), "{}", texts[1]);
        assert!(texts[1].contains("(credential field) Old password"), "{}", texts[1]);
        assert!(texts[3].contains(&format!("zoom {old_password}")), "{}", texts[3]);
    }

    #[test]
    fn a_ref_from_the_page_text_resolves_and_drives_a_real_click() {
        let (observation, url) = fixture_observation(X_LIKE);
        let article = ref_of(&observation, "article", None);
        let zoomed = render_fixture(&observation, &url, Some(&article), 65_536);
        // Take the post's timestamp link as printed, the way a caller would.
        let line = zoomed
            .text
            .lines()
            .find(|line| line.contains("link 19 minutes ago"))
            .unwrap();
        let reference = line.split_whitespace().next().unwrap();
        let id = new_snapshot_id("page-text-click");
        let mut store = BrowserSnapshotStore::new(1).unwrap();
        let printed: Vec<_> = observation
            .refs
            .iter()
            .filter(|record| zoomed.printed_refs.contains(&record.captured.reference))
            .cloned()
            .collect();
        store
            .retain_text(TextSnapshot {
                snapshot_id: id.clone(),
                kind: SnapshotKind::Actionable,
                document_epoch: 7,
                source_origin: url.clone(),
                source_document: None,
                content_schema: crate::snapshot_store::STATE_TEXT_SCHEMA,
                content: zoomed.text.clone(),
                truncated: false,
                refs_truncated: false,
                refs: printed.clone(),
            })
            .unwrap();
        let candidates: Vec<_> = printed
            .iter()
            .enumerate()
            .map(|(i, r)| RefCandidate {
                identity: r.backend_identity.clone(),
                frame_path: r.frame_path.clone(),
                role: r.captured.role.clone(),
                name: r.captured.name.clone(),
                traversal_index: i,
            })
            .collect();
        let RefResolution::Resolved(resolved) =
            store.resolve_ref(&id, reference, 7, &candidates).unwrap()
        else {
            panic!("a printed ref must resolve");
        };
        let backend = resolved.backend_identity.as_ref().unwrap().backend_node_id;
        let quad = json!([[10.0, 20.0, 34.0, 20.0, 34.0, 52.0, 10.0, 52.0]]);
        let mut driver = attached_driver([
            json!({"id":1,"sessionId":"session-own","result":{"quads":quad}}),
            json!({"id":2,"sessionId":"session-own","result":{}}),
            json!({"id":3,"sessionId":"session-own","result":{"quads":quad}}),
            json!({"id":4,"sessionId":"session-own","result":layout_metrics(0.0,0.0,1280.0,713.0)}),
            json!({"id":5,"sessionId":"session-own","result":{"backendNodeId":backend,"frameId":"frame-main"}}),
            json!({"id":6,"sessionId":"session-own","result":{}}),
            json!({"id":7,"sessionId":"session-own","result":{}}),
            json!({"id":8,"sessionId":"session-own","result":{}}),
            json!({"id":9,"sessionId":"session-own","result":{}}),
        ]);
        let mut events = Vec::new();
        driver
            .click_for_test(
                "route-own",
                resolved.backend_identity.as_ref().unwrap(),
                1000,
                &mut |event| events.push(event),
                &mut FakeClock::new(),
            )
            .unwrap();
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn link_urls_states_and_dom_facts_reach_the_observation() {
        let (observation, _) = fixture_observation(X_LIKE);
        let home = ref_of(&observation, "link", Some("Home"));
        let explore = ref_of(&observation, "link", Some("Explore"));
        let tab = ref_of(&observation, "tab", Some("For you"));
        let search = ref_of(&observation, "searchbox", None);
        // Chrome's own absolute URL wins; a bare href is resolved against the page.
        assert_eq!(observation.facts[&home].url.as_deref(), Some("https://example.com/home"));
        assert_eq!(observation.facts[&explore].url.as_deref(), Some("https://example.com/explore"));
        assert_eq!(observation.facts[&tab].states, ["selected"]);
        assert_eq!(observation.facts[&search].credential, Some(false));
        assert_eq!(observation.facts[&search].placeholder.as_deref(), Some("Search"));
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
                source_document: None,
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
        tracker.request_started();
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
            "settled while more than one request was still in flight"
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
    fn loaded_websocket_and_long_poll_settle_within_quiet_window() {
        let driver = attached_driver([]);
        let mut tracker = Tracker::default();
        let now = Instant::now();
        for (id, kind) in [("socket", "WebSocket"), ("poll", "Fetch")] {
            driver.apply_event(
                "route-own",
                &mut tracker,
                &event(
                    "Network.requestWillBeSent",
                    json!({"requestId":id,"type":kind}),
                ),
                now,
            );
        }
        driver.apply_event(
            "route-own",
            &mut tracker,
            &event("Page.loadEventFired", json!({})),
            now,
        );
        assert!(tracker.poll_settlement(now + Duration::from_millis(QUIET_MS)));
    }

    #[test]
    fn old_requests_and_event_streams_do_not_prevent_quiet() {
        let driver = attached_driver([]);
        let mut tracker = Tracker::default();
        let now = Instant::now();
        for id in ["poll1", "poll2", "stream1", "stream2"] {
            driver.apply_event(
                "route-own",
                &mut tracker,
                &event(
                    "Network.requestWillBeSent",
                    json!({"requestId":id,"type":"Fetch"}),
                ),
                now,
            );
        }
        for id in ["stream1", "stream2"] {
            driver.apply_event(
                "route-own",
                &mut tracker,
                &event(
                    "Network.responseReceived",
                    json!({"requestId":id,"type":"EventSource"}),
                ),
                now,
            );
        }
        tracker.load(now);
        assert!(!tracker.poll_settlement(now + Duration::from_millis(QUIET_MS)));
        let mut streams_only = tracker.clone();
        for id in ["poll1", "poll2"] {
            streams_only.network_request_finished(id, now);
        }
        assert!(streams_only.poll_settlement(now + Duration::from_millis(QUIET_MS)));
        let aged = now + Duration::from_secs(3);
        assert!(!tracker.poll_settlement(aged));
        assert!(tracker.poll_settlement(aged + Duration::from_millis(QUIET_MS)));
    }

    #[test]
    fn loaded_but_busy_deadline_is_ok_not_settled() {
        let mut driver = attached_driver([]);
        let mut tracker = Tracker::default();
        let mut clock = FakeClock::new();
        tracker.main_frame_navigated(Some("target-own".into()), "https://example.com".into());
        tracker.load(clock.now());
        // Overlapping short requests keep the count above the quiet threshold
        // through the deadline without any request becoming a long poll.
        for turn in 0..4 {
            for id in ["short1", "short2"] {
                driver.apply_event(
                    "route-own",
                    &mut tracker,
                    &event(
                        "Network.requestWillBeSent",
                        json!({"requestId":id,"type":"Fetch"}),
                    ),
                    clock.now(),
                );
            }
            let deadline = clock.now() + Duration::from_millis(200);
            driver
                .settle_navigation("route-own", &mut tracker, deadline, |_| false, &mut clock)
                .unwrap();
            if turn < 3 {
                for id in ["short1", "short2"] {
                    driver.apply_event(
                        "route-own",
                        &mut tracker,
                        &event("Network.loadingFinished", json!({"requestId":id})),
                        clock.now(),
                    );
                }
            }
        }
        let reply = super::super::navigate_reply(&tracker, true);
        assert_eq!(reply["outcome"], "ok");
        assert_eq!(reply["lifecycle"]["loaded"], true);
        assert_eq!(reply["lifecycle"]["settled"], false);
        assert!(reply.get("remedy").is_none());
    }

    #[test]
    fn uncommitted_document_deadline_reports_what_is_pending() {
        let mut driver = attached_driver([]);
        let mut tracker = Tracker::default();
        let mut clock = FakeClock::new();
        let deadline = clock.now() + Duration::from_millis(QUIET_MS + 1);
        driver
            .settle_navigation("route-own", &mut tracker, deadline, |_| false, &mut clock)
            .unwrap();
        let reply = super::super::navigate_reply(&tracker, true);
        assert_eq!(reply["outcome"], "not_settled");
        assert_eq!(reply["lifecycle"]["loaded"], false);
        assert!(reply["remedy"]
            .as_str()
            .unwrap()
            .contains("main document has not committed"));
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
        in_flight.inflight_count = 2;
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

/// The session-verification tab, driven against a pipe that answers each
/// command as Chrome would. Answers are produced when a command is written,
/// so a response can never arrive before the command it answers.
#[cfg(test)]
mod verification_tests {
    use std::collections::VecDeque;
    use std::io;

    use serde_json::json;

    use super::*;

    /// How the fake browser answers one command: its result or error, and
    /// the events it emits right after.
    type Answer = (Result<Value, Value>, Vec<Value>);
    type Answerer = Box<dyn FnMut(&str, &Value) -> Answer>;

    struct RespondingPipe {
        writes: Vec<Value>,
        reads: VecDeque<Vec<u8>>,
        answer: Answerer,
    }

    impl CdpPipeIo for RespondingPipe {
        fn write_frame(&mut self, bytes: &[u8]) -> io::Result<()> {
            let command: Value = serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap();
            let method = command["method"].as_str().unwrap().to_string();
            let (outcome, events) = (self.answer)(&method, &command);
            let mut response = json!({"id": command["id"]});
            if let Some(session_id) = command.get("sessionId") {
                response["sessionId"] = session_id.clone();
            }
            match outcome {
                Ok(result) => response["result"] = result,
                Err(error) => response["error"] = error,
            }
            for frame in std::iter::once(response).chain(events) {
                let mut bytes = serde_json::to_vec(&frame).unwrap();
                bytes.push(0);
                self.reads.push_back(bytes);
            }
            self.writes.push(command);
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

    struct StepClock(Instant);

    impl NavigationClock for StepClock {
        fn now(&mut self) -> Instant {
            self.0
        }

        fn sleep(&mut self, duration: Duration) {
            self.0 += duration;
        }
    }

    const TAB: &str = "verify-tab";
    const SESSION: &str = "verify-session";

    fn event(method: &str, params: Value) -> Value {
        json!({"method": method, "sessionId": SESSION, "params": params})
    }

    fn document_response(frame_id: &str, status: u64) -> Value {
        event(
            "Network.responseReceived",
            json!({"type": "Document", "frameId": frame_id, "requestId": "r", "response": {"status": status}}),
        )
    }

    fn committed(url: &str) -> Value {
        event(
            "Page.frameNavigated",
            json!({"frame": {"id": TAB, "url": url}}),
        )
    }

    /// The page the tab ends on.
    struct Ending {
        url: &'static str,
        /// Events Chrome emits after `Page.navigate` answers.
        events: Vec<Value>,
        credential_boxes: Vec<Result<(f64, f64), ()>>,
        close_fails: bool,
    }

    fn signed_in_page() -> Ending {
        Ending {
            url: "https://ollama.com/settings",
            events: vec![
                document_response(TAB, 200),
                committed("https://ollama.com/settings"),
                event("Page.loadEventFired", json!({})),
            ],
            credential_boxes: Vec::new(),
            close_fails: false,
        }
    }

    fn browser(ending: Ending) -> CdpNavigationDriver<RespondingPipe> {
        let Ending {
            url,
            mut events,
            credential_boxes,
            close_fails,
        } = ending;
        let mut boxes = credential_boxes.clone().into_iter();
        let answer = move |method: &str, command: &Value| -> Answer {
            let ok = |result: Value| (Ok(result), Vec::new());
            match method {
                "Target.createTarget" => ok(json!({"targetId": TAB})),
                "Target.attachToTarget" => ok(json!({"sessionId": SESSION})),
                "Page.navigate" => (
                    Ok(json!({"frameId": TAB, "loaderId": "loader"})),
                    std::mem::take(&mut events),
                ),
                "Page.getNavigationHistory" => {
                    ok(json!({"currentIndex": 0, "entries": [{"id": 1, "url": url}]}))
                }
                "DOM.getDocument" => ok(json!({"root": {"nodeId": 1}})),
                "DOM.querySelectorAll" => ok(json!({
                    "nodeIds": (0..credential_boxes.len()).map(|index| index + 10).collect::<Vec<_>>()
                })),
                "DOM.getBoxModel" => match boxes.next() {
                    Some(Ok((width, height))) => {
                        ok(json!({"model": {"width": width, "height": height}}))
                    }
                    _ => (
                        Err(json!({"code": -32000, "message": "Could not compute box model."})),
                        Vec::new(),
                    ),
                },
                "Target.closeTarget" if close_fails => (
                    Err(json!({"code": -32000, "message": "close refused"})),
                    Vec::new(),
                ),
                // The tab still exists whenever its close was refused.
                "Target.getTargetInfo" => {
                    ok(json!({"targetInfo": {"targetId": command["params"]["targetId"]}}))
                }
                _ => ok(json!({})),
            }
        };
        let mut driver = CdpNavigationDriver::new(
            RespondingPipe {
                writes: Vec::new(),
                reads: VecDeque::new(),
                answer: Box::new(answer),
            },
            CdpTransport::new(),
            CdpFrameDecoder::default(),
        );
        // The person's own sign-in page, attached the way a capture attaches
        // it, so the test can show nothing is sent to it.
        driver
            .identities
            .attach(Attachment {
                target_id: "person-tab".into(),
                session_id: "person-session".into(),
                frame_ids: Vec::new(),
                context_key: "browser.capture_login".into(),
            })
            .unwrap();
        driver.attachment = Some(AttachedTarget {
            target_id: "person-tab".into(),
            session_id: "person-session".into(),
            context_key: "browser.capture_login".into(),
        });
        driver
    }

    fn verify(
        driver: &mut CdpNavigationDriver<RespondingPipe>,
    ) -> Result<crate::login_capture::SessionProbe, NavigationDriveError> {
        driver.load_in_background_tab_with_clock(
            "https://ollama.com/settings",
            5_000,
            &mut StepClock(Instant::now()),
        )
    }

    fn methods(driver: &CdpNavigationDriver<RespondingPipe>) -> Vec<String> {
        driver
            .pipe
            .writes
            .iter()
            .map(|write| write["method"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn a_verification_loads_in_a_background_tab_and_closes_it() {
        let mut driver = browser(signed_in_page());
        let probe = verify(&mut driver).unwrap();
        assert_eq!(
            probe,
            crate::login_capture::SessionProbe {
                final_url: "https://ollama.com/settings".to_string(),
                status: Some(200),
                credential_field: false,
            }
        );
        assert_eq!(
            methods(&driver),
            [
                "Target.createTarget",
                "Target.attachToTarget",
                "Page.enable",
                "Network.enable",
                "Page.navigate",
                "Page.getNavigationHistory",
                "DOM.getDocument",
                "DOM.querySelectorAll",
                "Target.closeTarget",
            ]
        );
        let created = &driver.pipe.writes[0]["params"];
        assert_eq!(created["background"], true, "{created}");
        assert_eq!(created["url"], "about:blank");
        assert_eq!(driver.pipe.writes[8]["params"]["targetId"], TAB);
        for write in &driver.pipe.writes {
            assert_ne!(
                write.get("sessionId").and_then(Value::as_str),
                Some("person-session"),
                "a verification sent {write} to the person's page"
            );
            assert!(
                !write["method"].as_str().unwrap().starts_with("Runtime."),
                "a verification enabled or used Runtime: {write}"
            );
        }
        assert_eq!(driver.unclosed_verification_target, None);
    }

    /// The status is the main frame's own: a redirect hop sends no document
    /// response, and a subframe's document response is not the page's.
    #[test]
    fn the_status_is_the_main_documents_and_the_url_is_where_it_ended() {
        let mut driver = browser(Ending {
            url: "https://ollama.com/signin?next=%2Fsettings",
            events: vec![
                document_response(TAB, 401),
                committed("https://ollama.com/signin?next=%2Fsettings"),
                document_response("an-iframe", 200),
                event("Page.loadEventFired", json!({})),
            ],
            ..signed_in_page()
        });
        let probe = verify(&mut driver).unwrap();
        assert_eq!(probe.status, Some(401));
        assert_eq!(
            probe.final_url,
            "https://ollama.com/signin?next=%2Fsettings"
        );
    }

    /// The blank page the tab opens on fires its own load event; that is not
    /// the requested page loading, so the verification keeps waiting and, with
    /// nothing else arriving, runs out of time and still closes its tab.
    #[test]
    fn a_load_that_never_finishes_fails_and_still_closes_the_tab() {
        let mut driver = browser(Ending {
            events: vec![
                committed("about:blank"),
                event("Page.loadEventFired", json!({})),
            ],
            ..signed_in_page()
        });
        assert!(verify(&mut driver).is_err());
        assert_eq!(methods(&driver).last().unwrap(), "Target.closeTarget");
    }

    /// A commit after the load event is a script redirect, so the load that
    /// counts is the one after it.
    #[test]
    fn a_script_redirect_after_load_is_waited_for() {
        let mut driver = browser(Ending {
            url: "https://ollama.com/login",
            events: vec![
                document_response(TAB, 200),
                committed("https://ollama.com/settings"),
                event("Page.loadEventFired", json!({})),
                committed("https://ollama.com/login"),
            ],
            ..signed_in_page()
        });
        assert!(
            verify(&mut driver).is_err(),
            "the second document never loaded, so nothing settled"
        );
    }

    #[test]
    fn only_a_rendered_credential_field_counts() {
        let mut hidden = browser(Ending {
            credential_boxes: vec![Err(()), Ok((0.0, 0.0))],
            ..signed_in_page()
        });
        assert!(!verify(&mut hidden).unwrap().credential_field);

        let mut shown = browser(Ending {
            credential_boxes: vec![Err(()), Ok((240.0, 32.0))],
            ..signed_in_page()
        });
        assert!(verify(&mut shown).unwrap().credential_field);
    }

    /// A tab whose close was refused is closed before another opens, and while
    /// it cannot be closed no second tab is ever opened.
    #[test]
    fn a_tab_that_would_not_close_blocks_the_next_one() {
        let mut driver = browser(Ending {
            close_fails: true,
            ..signed_in_page()
        });
        assert!(
            verify(&mut driver).is_ok(),
            "what the load saw stands even when its tab would not close"
        );
        assert_eq!(driver.unclosed_verification_target.as_deref(), Some(TAB));
        let before = driver.pipe.writes.len();
        assert!(verify(&mut driver).is_err());
        let after = methods(&driver)[before..].to_vec();
        assert_eq!(after, ["Target.closeTarget", "Target.getTargetInfo"]);
    }
}

/// Reading a page after a person signed in on it, against a pipe that
/// answers each command with the bytes Chrome sent for that page.
#[cfg(test)]
mod signed_in_page_read_tests {
    use std::collections::VecDeque;
    use std::io;

    use super::*;

    const TARGET: &str = "target-own";
    const SESSION: &str = "session-own";
    const ROUTE: &str = "route-own";

    /// Answers each command written to it with Chrome's response written out
    /// as raw JSON text. A `serde_json::Value` cannot hold an unpaired
    /// surrogate half, so these bytes could not be produced by serializing one.
    struct ChromeBytesPipe {
        methods: Vec<String>,
        reads: VecDeque<Vec<u8>>,
    }

    impl ChromeBytesPipe {
        /// The `result` member Chrome answered each command with, and the
        /// events it sent right after, as raw JSON text.
        fn answer(method: &str) -> (&'static str, Vec<&'static str>) {
            match method {
                "Page.getNavigationHistory" => (
                    r#"{"currentIndex":1,"entries":[{"id":7,"url":"about:blank","userTypedURL":"about:blank","title":"","transitionType":"auto_toplevel"},{"id":46,"url":"https://x.com/home","userTypedURL":"https://x.com/home","title":"Home","transitionType":"link"}]}"#,
                    Vec::new(),
                ),
                "Page.getFrameTree" => (
                    r#"{"frameTree":{"frame":{"id":"target-own","loaderId":"E02D954DD0558A31A413AC49B889D821","url":"https://x.com/home","securityOrigin":"https://x.com","mimeType":"text/html"}}}"#,
                    Vec::new(),
                ),
                "Accessibility.getRootAXNode" => (
                    r#"{"node":{"nodeId":"86","ignored":false,"role":{"type":"internalRole","value":"RootWebArea"},"chromeRole":{"type":"internalRole","value":144},"name":{"type":"computedString","value":"Home"},"properties":[],"childIds":["93"],"backendDOMNodeId":86,"frameId":"target-own"}}"#,
                    Vec::new(),
                ),
                // A button whose text a script set to "cut " followed by the
                // first half of an emoji's surrogate pair. These are the bytes
                // Chrome 154 answered with for it, as logged by
                // `examples/handoff_attachment_probe.rs`.
                "Accessibility.getChildAXNodes" => (
                    r#"{"nodes":[{"nodeId":"93","ignored":false,"role":{"type":"role","value":"button"},"chromeRole":{"type":"internalRole","value":9},"name":{"type":"computedString","value":"cut \ud83d","sources":[{"type":"relatedElement","attribute":"aria-labelledby"},{"type":"attribute","attribute":"aria-label"},{"type":"relatedElement","nativeSource":"label"},{"type":"contents","value":{"type":"computedString","value":"cut \ud83d"}},{"type":"attribute","attribute":"title","superseded":true}]},"properties":[{"name":"invalid","value":{"type":"token","value":"false"}},{"name":"focusable","value":{"type":"booleanOrUndefined","value":true}}],"parentId":"86","childIds":[],"backendDOMNodeId":93}]}"#,
                    Vec::new(),
                ),
                // Once the DOM domain is on, Chrome reports the page's text
                // changes, with the same unpaired half in them.
                "DOM.enable" => (
                    "{}",
                    vec![
                        r#"{"method":"DOM.characterDataModified","params":{"nodeId":94,"characterData":"cut \udc00 again"},"sessionId":"session-own"}"#,
                    ],
                ),
                "DOM.getFlattenedDocument" => (r#"{"nodes":[]}"#, Vec::new()),
                _ => ("{}", Vec::new()),
            }
        }
    }

    impl CdpPipeIo for ChromeBytesPipe {
        fn write_frame(&mut self, bytes: &[u8]) -> io::Result<()> {
            let command: Value = serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap();
            let method = command["method"].as_str().unwrap().to_string();
            let (result, events) = Self::answer(&method);
            let response = format!(
                r#"{{"id":{},"result":{result},"sessionId":{}}}"#,
                command["id"], command["sessionId"]
            );
            for frame in std::iter::once(response).chain(events.into_iter().map(String::from)) {
                let mut bytes = frame.into_bytes();
                bytes.push(0);
                self.reads.push_back(bytes);
            }
            self.methods.push(method);
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

    struct StepClock(Instant);

    impl NavigationClock for StepClock {
        fn now(&mut self) -> Instant {
            self.0
        }

        fn sleep(&mut self, duration: Duration) {
            self.0 += duration;
        }
    }

    fn signed_in_driver() -> CdpNavigationDriver<ChromeBytesPipe> {
        let mut driver = CdpNavigationDriver::new(
            ChromeBytesPipe {
                methods: Vec::new(),
                reads: VecDeque::new(),
            },
            CdpTransport::new(),
            CdpFrameDecoder::default(),
        );
        driver
            .identities
            .attach(Attachment {
                target_id: TARGET.into(),
                session_id: SESSION.into(),
                frame_ids: Vec::new(),
                context_key: ROUTE.into(),
            })
            .unwrap();
        driver.attachment = Some(AttachedTarget {
            target_id: TARGET.into(),
            session_id: SESSION.into(),
            context_key: ROUTE.into(),
        });
        driver
    }

    /// `browser.snapshot` reads the committed document, captures the page,
    /// and reads the committed document again. Every step must succeed on a
    /// page whose text Chrome sends with an unpaired surrogate half, and the
    /// half reads as the replacement character.
    #[test]
    fn a_page_whose_text_holds_half_a_surrogate_pair_can_still_be_read() {
        let mut driver = signed_in_driver();
        let clock = &mut StepClock(Instant::now());

        let before = driver
            .committed_document_with_clock(ROUTE, 5_000, clock)
            .expect("committed document before the capture");
        assert_eq!(before.url, "https://x.com/home");
        let observation = driver
            .snapshot_with_clock(
                ROUTE,
                SnapshotKind::Actionable,
                5_000,
                Some((1, before.url.as_str())),
                clock,
            )
            .expect("the capture reads the page");
        assert!(
            observation
                .records
                .iter()
                .any(|record| record.role == "button" && record.name == "cut \u{fffd}"),
            "{:?}",
            observation.records
        );
        let after = driver
            .committed_document_with_clock(ROUTE, 5_000, clock)
            .expect("committed document after the capture");
        assert_eq!(after, before);
        assert!(
            driver.pipe.methods.contains(&"DOM.enable".to_string()),
            "the read must reach the point where Chrome sends DOM events"
        );
    }
}
