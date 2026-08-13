use std::cmp;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use serde_json::{Map, Value};

use crate::browser::Tracker;
use crate::browser_launch_readiness::{CdpPipeIo, PipeRead};
use crate::browser_session::{NavigationDriveError, NavigationWait};
use crate::cdp::{Attachment, CdpEvent, CdpFrameDecoder, CdpResponse, CdpTransport, IdentityMap};
use crate::snapshot_store::{
    truncate_ax_field, AxRecord, BackendNodeIdentity, RefRecord, SnapshotKind, SnapshotRef,
    MAX_NAME_BYTES, MAX_REFS, MAX_ROLE_BYTES, MAX_VALUE_BYTES,
};

const READ_CHUNK_BYTES: usize = 64 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const MAX_AX_NODES: usize = MAX_REFS;
const MAX_AX_DEPTH: usize = 64;

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

/// Owns every CDP write, frame decoder, and request correlator for one browser.
/// Keeping these together prevents a lifecycle command and a navigation command
/// from assigning competing request ids or interleaving frames on the pipe.
pub(crate) struct CdpNavigationDriver<IO> {
    pipe: IO,
    transport: CdpTransport,
    decoder: CdpFrameDecoder,
    identities: IdentityMap,
    attachment: Option<AttachedTarget>,
    read_buffer: Vec<u8>,
}

impl<IO: CdpPipeIo> CdpNavigationDriver<IO> {
    pub(crate) fn new(pipe: IO, mut transport: CdpTransport, decoder: CdpFrameDecoder) -> Self {
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
            read_buffer: vec![0; READ_CHUNK_BYTES],
        }
    }

    pub(crate) fn navigate(
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

    pub(crate) fn snapshot(
        &mut self,
        context_key: &str,
        mode: SnapshotKind,
        deadline_ms: u64,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        let mut clock = SystemNavigationClock;
        self.snapshot_with_clock(context_key, mode, deadline_ms, &mut clock)
    }

    #[cfg(test)]
    fn snapshot_for_test<C: NavigationClock>(
        &mut self,
        context_key: &str,
        mode: SnapshotKind,
        deadline_ms: u64,
        clock: &mut C,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        self.snapshot_with_clock(context_key, mode, deadline_ms, clock)
    }

    fn snapshot_with_clock<C: NavigationClock>(
        &mut self,
        context_key: &str,
        mode: SnapshotKind,
        deadline_ms: u64,
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
        self.command(
            "Page.navigate",
            Some(params),
            Some(attachment.session_id.clone()),
            deadline,
            Some((context_key, tracker)),
            clock,
        )?;

        if wait == NavigationWait::None {
            return Ok(());
        }

        while clock.now() < deadline {
            self.read_turn(None, Some((context_key, tracker)), clock.now())?;
            if tracker.poll_settlement(clock.now()) {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(clock.now());
            clock.sleep(cmp::min(POLL_INTERVAL, remaining));
        }
        tracker.poll_settlement(clock.now());
        Ok(())
    }

    pub(crate) fn request_browser_close(&mut self) -> Result<(), NavigationDriveError> {
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
        let mut create_params = Map::new();
        create_params.insert("url".into(), Value::String("about:blank".into()));
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
        mut tracking: Option<(&str, &mut Tracker)>,
        clock: &mut C,
    ) -> Result<Map<String, Value>, NavigationDriveError> {
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

        loop {
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
            if let Some(response) = response {
                if response.error.is_some() {
                    return Err(NavigationDriveError::CdpFailure);
                }
                return response.result.ok_or(NavigationDriveError::CdpFailure);
            }
            let remaining = deadline.saturating_duration_since(clock.now());
            clock.sleep(cmp::min(POLL_INTERVAL, remaining));
        }
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
                }
                continue;
            }

            let event = self
                .transport
                .accept_event(&frame)
                .map_err(|_| NavigationDriveError::CdpFailure)?;
            let _ = self.transport.pop_event();
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
            }
            "Network.loadingFinished" | "Network.loadingFailed" => {
                tracker.request_finished(observed_at)
            }
            "Page.frameNavigated" => {
                let frame = event
                    .params
                    .as_ref()
                    .and_then(|params| params.get("frame"))
                    .and_then(Value::as_object);
                if let Some(frame) = frame.filter(|frame| !frame.contains_key("parentId")) {
                    if let Some(url) = frame.get("url").and_then(Value::as_str) {
                        tracker.url_final = Some(url.to_string());
                    }
                }
            }
            _ => {}
        }
    }
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
            RefResolution::Resolved(captured)
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
}
