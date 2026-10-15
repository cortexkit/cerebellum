use super::*;
use crate::snapshot_store::FrameDocument;

impl<IO: CdpPipeIo> CdpNavigationDriver<IO> {
    pub fn frame_documents(
        &mut self,
        context: &str,
        deadline_ms: u64,
    ) -> Result<Vec<FrameDocument>, NavigationDriveError> {
        let mut clock = SystemNavigationClock;
        let deadline = clock.now() + Duration::from_millis(deadline_ms);
        self.ensure_attached(context, deadline, &mut clock)?;
        let attachment = self
            .attachment
            .clone()
            .ok_or_else(|| NavigationDriveError::CdpFailure.at_step("Target.attachToTarget"))?;
        self.configure_frame_session(&attachment.session_id, deadline, &mut clock)?;
        let tree = self.command(
            "Page.getFrameTree",
            None,
            Some(attachment.session_id.clone()),
            deadline,
            None,
            &mut clock,
        )?;
        let mut documents = Vec::new();
        self.collect_frame_documents(
            tree.get("frameTree")
                .ok_or_else(|| NavigationDriveError::CdpFailure.at_step("Page.getFrameTree"))?,
            None,
            &attachment.session_id,
            &mut documents,
        )
        .map_err(|error| error.at_step("Page.getFrameTree"))?;
        // Page.getFrameTree on the parent can omit descendants of an OOPIF.
        let mut queried = HashSet::new();
        // Configuring a child recursively auto-attaches its own OOPIFs. Drain
        // that expanding set rather than taking a one-time list of sessions.
        loop {
            let mut pending: Vec<_> = self
                .frame_sessions
                .values()
                .filter(|session| !queried.contains(*session))
                .cloned()
                .collect();
            pending.sort();
            let Some(session) = pending.into_iter().next() else {
                break;
            };
            if queried.len() >= 128 {
                return Err(NavigationDriveError::CdpFailure.at_step("Page.getFrameTree"));
            }
            self.configure_frame_session(&session, deadline, &mut clock)?;
            queried.insert(session.clone());
            let tree = self.command(
                "Page.getFrameTree",
                None,
                Some(session.clone()),
                deadline,
                None,
                &mut clock,
            )?;
            let root = tree
                .get("frameTree")
                .ok_or_else(|| NavigationDriveError::CdpFailure.at_step("Page.getFrameTree"))?;
            let id = root
                .pointer("/frame/id")
                .and_then(Value::as_str)
                .ok_or_else(|| NavigationDriveError::CdpFailure.at_step("Page.getFrameTree"))?;
            let parent = documents
                .iter()
                .find(|d| d.frame_id == id)
                .and_then(|d| d.parent_id.clone());
            self.collect_frame_documents(root, parent.as_deref(), &session, &mut documents)
                .map_err(|error| error.at_step("Page.getFrameTree"))?;
        }
        let ancestry = documents.clone();
        documents.sort_by_key(|d| {
            let mut depth = 0;
            let mut parent = d.parent_id.as_deref();
            while let Some(id) = parent {
                depth += 1;
                if depth >= MAX_AX_DEPTH {
                    break;
                }
                parent = ancestry
                    .iter()
                    .find(|p| p.frame_id == id)
                    .and_then(|p| p.parent_id.as_deref());
            }
            (depth, d.frame_id.clone())
        });
        self.frame_documents = documents.clone();
        Ok(documents)
    }

    fn configure_frame_session<C: NavigationClock>(
        &mut self,
        session: &str,
        deadline: Instant,
        clock: &mut C,
    ) -> Result<(), NavigationDriveError> {
        if self.configured_frame_sessions.contains(session) {
            return Ok(());
        }
        self.command("Target.setAutoAttach", Some(serde_json::json!({"autoAttach":true,"waitForDebuggerOnStart":false,"flatten":true}).as_object().unwrap().clone()), Some(session.into()), deadline, None, clock)?;
        self.command(
            "Page.enable",
            None,
            Some(session.into()),
            deadline,
            None,
            clock,
        )?;
        self.configured_frame_sessions.insert(session.into());
        Ok(())
    }

    fn collect_frame_documents(
        &self,
        tree: &Value,
        parent: Option<&str>,
        inherited_session: &str,
        documents: &mut Vec<FrameDocument>,
    ) -> Result<(), NavigationDriveError> {
        if documents.len() >= 128 {
            return Err(NavigationDriveError::CdpFailure);
        }
        let frame = tree.get("frame").ok_or(NavigationDriveError::CdpFailure)?;
        let text = |key: &str| {
            frame
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or(NavigationDriveError::CdpFailure)
        };
        let id = text("id")?;
        let parent = parent.or_else(|| frame.get("parentId").and_then(Value::as_str));
        let url = text("url")?;
        let security_origin = frame
            .get("securityOrigin")
            .and_then(Value::as_str)
            .unwrap_or("null");
        let creator = parent.and_then(|id| documents.iter().find(|d| d.frame_id == id));
        // about:blank and srcdoc inherit their creator's origin unless Chrome
        // reports an opaque origin (for example a sandboxed frame).
        let origin = if let Some(origin) = classification::canonical_grant_origin(security_origin) {
            origin
        } else if matches!(url.as_str(), "about:blank" | "about:srcdoc")
            && frame.get("securityOrigin").is_none()
        {
            creator
                .map(|d| d.origin.clone())
                .unwrap_or_else(|| "null".into())
        } else {
            "null".into()
        };
        let document = FrameDocument {
            navigation_revision: self.frame_revisions.get(&id).copied().unwrap_or(0),
            frame_id: id.clone(),
            parent_id: parent.map(str::to_string),
            session_id: self.frame_sessions.get(&id).cloned().unwrap_or_else(|| {
                creator
                    .map(|d| d.session_id.clone())
                    .unwrap_or_else(|| inherited_session.into())
            }),
            loader_id: text("loaderId")?,
            url,
            origin,
        };
        if let Some(index) = documents.iter().position(|d| d.frame_id == id) {
            documents[index] = document;
        } else {
            documents.push(document);
        }
        if let Some(children) = tree.get("childFrames").and_then(Value::as_array) {
            for child in children {
                self.collect_frame_documents(child, Some(&id), inherited_session, documents)?;
            }
        }
        Ok(())
    }

    pub(super) fn observe_frame_session(&mut self, event: &CdpEvent) {
        let owned = event.session_id.as_ref().is_some_and(|s| {
            self.attachment.as_ref().is_some_and(|a| &a.session_id == s)
                || self.frame_sessions.values().any(|v| v == s)
        });
        if !owned {
            return;
        }
        let Some(params) = event.params.as_ref() else {
            return;
        };
        if matches!(
            event.method.as_str(),
            "Page.frameNavigated" | "Page.navigatedWithinDocument" | "Page.frameDetached"
        ) {
            if let Some(frame) = params.get("frameId").and_then(Value::as_str).or_else(|| {
                params
                    .get("frame")
                    .and_then(|f| f.get("id"))
                    .and_then(Value::as_str)
            }) {
                let revision = self.frame_revisions.entry(frame.into()).or_default();
                *revision = revision.saturating_add(1);
            }
        }
        match event.method.as_str() {
            "Target.attachedToTarget"
                if params
                    .get("targetInfo")
                    .and_then(|v| v.get("type"))
                    .and_then(Value::as_str)
                    == Some("iframe") =>
            {
                if let (Some(frame), Some(session)) = (
                    params
                        .get("targetInfo")
                        .and_then(|v| v.get("targetId"))
                        .and_then(Value::as_str),
                    params.get("sessionId").and_then(Value::as_str),
                ) {
                    self.frame_sessions.insert(frame.into(), session.into());
                }
            }
            "Target.detachedFromTarget" => {
                if let Some(session) = params.get("sessionId").and_then(Value::as_str) {
                    self.frame_sessions.retain(|_, value| value != session);
                    self.configured_frame_sessions.remove(session);
                    self.focus_emulated_sessions.remove(session);
                }
            }
            _ => {}
        }
    }

    pub fn set_read_frames(&mut self, frames: Vec<FrameDocument>) {
        self.read_frames = Some(frames);
    }

    pub fn prepare_frame(
        &mut self,
        context: &str,
        expected: &FrameDocument,
        deadline_ms: u64,
    ) -> Result<bool, NavigationDriveError> {
        self.active_frame = None;
        let live = self.frame_documents(context, deadline_ms)?;
        let Some(current) = live.iter().find(|frame| frame.same_document(expected)) else {
            return Ok(false);
        };
        self.active_frame = Some(current.clone());
        Ok(true)
    }

    pub fn point_frame_document(&self) -> Option<FrameDocument> {
        self.point_frame.clone()
    }

    pub(super) fn frame_attachment(
        &self,
        identity: &BackendNodeIdentity,
    ) -> Result<AttachedTarget, NavigationDriveError> {
        let mut attachment = self
            .attachment
            .clone()
            .filter(|a| a.target_id == identity.target_id)
            .ok_or(NavigationDriveError::CdpFailure)?;
        if let Some(frame) = self
            .active_frame
            .as_ref()
            .filter(|f| f.frame_id == identity.frame_id)
        {
            attachment.session_id = frame.session_id.clone();
        }
        Ok(attachment)
    }
}

impl<IO: CdpPipeIo> CdpNavigationDriver<IO> {
    pub(super) fn snapshot_all_frames<C: NavigationClock>(
        &mut self,
        context: &str,
        mode: SnapshotKind,
        deadline_ms: u64,
        classification: Option<(u64, &str)>,
        subtree: Option<&RefRecord>,
        clock: &mut C,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        let allowed = self
            .read_frames
            .take()
            .ok_or_else(|| NavigationDriveError::CdpFailure.at_step("Page.getFrameTree"))?;
        let before = self.frame_documents.clone();
        let mut omitted_frames = HashSet::new();
        // A zoom can include nested frame documents, but each must share one
        // absolute capture allowance rather than renew it for every frame.
        let subtree_deadline = subtree.map(|_| {
            clock.now()
                + Duration::from_millis(deadline_ms.min(crate::budgets::FRAME_SNAPSHOT_PHASE_MS))
        });
        let result = (|| {
            let main = before
                .iter()
                .find(
                    |f| match subtree.and_then(|r| r.backend_identity.as_ref()) {
                        Some(identity) => f.frame_id == identity.frame_id,
                        None => f.parent_id.is_none(),
                    },
                )
                .ok_or_else(|| NavigationDriveError::CdpFailure.at_step("Page.getFrameTree"))?;
            if let Some(expected) = subtree.and_then(|r| r.frame_document.as_ref()) {
                if !main.same_document(expected) {
                    return Err(NavigationDriveError::FrameChanged {
                        authorized_origin: expected.origin.clone(),
                        live_origin: main.origin.clone(),
                    });
                }
            }
            // Starting inside a frame must not bypass an unread ancestor document.
            let root_readable = std::iter::successors(Some(main), |frame| {
                frame.parent_id.as_ref().and_then(|parent| {
                    before
                        .iter()
                        .find(|candidate| &candidate.frame_id == parent)
                })
            })
            .all(|frame| allowed.contains(frame));
            if subtree.is_some() && !root_readable {
                // A previously printed ref is not permission to read a now
                // withheld embedded document. Return the permitted page's outline
                // so the caller can request a new ref without exposing that frame.
                self.read_frames = Some(allowed.clone());
                return self.snapshot_all_frames(
                    context,
                    mode,
                    deadline_ms,
                    classification,
                    None,
                    clock,
                );
            }
            if subtree.is_some() {
                let mut descendants = HashSet::from([main.frame_id.clone()]);
                for frame in &before {
                    if frame
                        .parent_id
                        .as_ref()
                        .is_some_and(|p| descendants.contains(p))
                    {
                        descendants.insert(frame.frame_id.clone());
                    }
                }
                omitted_frames.extend(
                    before
                        .iter()
                        .filter(|f| !descendants.contains(&f.frame_id))
                        .map(|f| f.frame_id.clone()),
                );
            }
            self.active_frame = Some(main.clone());
            let epoch = classification.map(|c| c.0);
            let mut observation = self.snapshot_with_clock(
                context,
                mode,
                subtree_deadline
                    .map(|end| end.saturating_duration_since(clock.now()).as_millis() as u64)
                    .unwrap_or(deadline_ms),
                epoch.map(|e| (e, main.origin.as_str())),
                subtree,
                clock,
            )?;
            for reference in &mut observation.refs {
                reference.frame_document = Some(main.clone());
            }
            for frame in before.iter().filter(|f| f.parent_id.is_some()) {
                if frame.frame_id == main.frame_id || omitted_frames.contains(&frame.frame_id) {
                    continue;
                }
                if frame
                    .parent_id
                    .as_ref()
                    .is_some_and(|parent| omitted_frames.contains(parent))
                {
                    omitted_frames.insert(frame.frame_id.clone());
                    continue;
                }
                let readable = allowed.contains(frame);
                if readable
                    && (observation.records.len() >= MAX_AX_NODES
                        || observation.refs.len() >= MAX_REFS)
                {
                    observation.ax_truncated = true;
                    observation.refs_truncated = true;
                    continue;
                }
                if frame
                    .parent_id
                    .as_ref()
                    .is_some_and(|id| !allowed.iter().any(|p| &p.frame_id == id))
                {
                    omitted_frames.insert(frame.frame_id.clone());
                    continue;
                }
                let parent = frame
                    .parent_id
                    .as_ref()
                    .and_then(|id| before.iter().find(|f| &f.frame_id == id))
                    .ok_or_else(|| NavigationDriveError::CdpFailure.at_step("Page.getFrameTree"))?;
                let deadline = subtree_deadline
                    .map(|end| snapshot_step_deadline(end, true, clock.now()))
                    .unwrap_or_else(|| clock.now() + Duration::from_millis(deadline_ms));
                let params = serde_json::json!({"frameId":frame.frame_id})
                    .as_object()
                    .unwrap()
                    .clone();
                let owner = match self.command(
                    "DOM.getFrameOwner",
                    Some(params),
                    Some(parent.session_id.clone()),
                    deadline,
                    None,
                    clock,
                ) {
                    Ok(owner) => owner,
                    Err(NavigationDriveError::NodeUnavailable { .. }) => {
                        observation.ax_truncated = true;
                        observation.refs_truncated = true;
                        omitted_frames.insert(frame.frame_id.clone());
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                let backend = owner
                    .get("backendNodeId")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| NavigationDriveError::CdpFailure.at_step("DOM.getFrameOwner"))?;
                let owner_ref = observation
                    .refs
                    .iter()
                    .find(|r| {
                        r.backend_identity.as_ref().is_some_and(|i| {
                            i.backend_node_id == backend && i.frame_id == parent.frame_id
                        })
                    })
                    .map(|r| r.captured.reference.clone());
                if !readable {
                    // A withheld document must not leave an actionable iframe
                    // owner pointing into it, even when the owner is in the parent.
                    if let Some(owner_ref) = owner_ref {
                        observation
                            .refs
                            .retain(|r| r.captured.reference != owner_ref);
                        for record in &mut observation.records {
                            if record.reference.as_deref() == Some(&owner_ref) {
                                record.reference = None;
                            }
                        }
                        observation.facts.remove(&owner_ref);
                    }
                    omitted_frames.insert(frame.frame_id.clone());
                    continue;
                }
                let owner_index = owner_ref.as_ref().and_then(|r| {
                    observation
                        .records
                        .iter()
                        .position(|n| n.reference.as_ref() == Some(r))
                });
                let Some(owner_index) = owner_index else {
                    // A hidden or replaced iframe has no visible owner to insert
                    // its content under. Skip its subtree rather than lose the page.
                    if subtree.is_none() {
                        observation.ax_truncated = true;
                        observation.refs_truncated = true;
                    }
                    omitted_frames.insert(frame.frame_id.clone());
                    continue;
                };
                let depth = observation.records[owner_index].depth + 1;
                self.active_frame = Some(frame.clone());
                let mut child = self.snapshot_frame_with_clock(
                    context,
                    mode,
                    subtree_deadline
                        .map(|end| end.saturating_duration_since(clock.now()).as_millis() as u64)
                        .unwrap_or(deadline_ms),
                    epoch.map(|e| (e, frame.origin.as_str())),
                    None,
                    subtree.is_some(),
                    clock,
                )?;
                let remaining_nodes = MAX_AX_NODES.saturating_sub(observation.records.len());
                if child.records.len() > remaining_nodes {
                    child.records.truncate(remaining_nodes);
                    child.ax_truncated = true;
                    child.refs_truncated = true;
                }
                let printed: HashSet<_> = child
                    .records
                    .iter()
                    .filter_map(|record| record.reference.as_ref())
                    .cloned()
                    .collect();
                child
                    .refs
                    .retain(|reference| printed.contains(&reference.captured.reference));
                let remaining_refs = MAX_REFS.saturating_sub(observation.refs.len());
                if child.refs.len() > remaining_refs {
                    child.refs.truncate(remaining_refs);
                    child.refs_truncated = true;
                }
                let retained: HashSet<_> = child
                    .refs
                    .iter()
                    .map(|r| r.captured.reference.clone())
                    .collect();
                for record in &mut child.records {
                    if record
                        .reference
                        .as_ref()
                        .is_some_and(|r| !retained.contains(r))
                    {
                        record.reference = None;
                    }
                }
                let offset = observation.refs.len();
                let mut names = HashMap::new();
                for (index, reference) in child.refs.iter_mut().enumerate() {
                    reference.frame_document = Some(frame.clone());
                    let old = reference.captured.reference.clone();
                    reference.captured.reference = format!("e{}", offset + index + 1);
                    names.insert(old, reference.captured.reference.clone());
                }
                for record in &mut child.records {
                    record.depth += depth;
                    if let Some(reference) = &mut record.reference {
                        *reference = names
                            .get(reference)
                            .ok_or_else(|| {
                                NavigationDriveError::CdpFailure
                                    .at_step("Accessibility.getChildAXNodes")
                            })?
                            .clone();
                    }
                }
                for (old, facts) in child.facts {
                    if let Some(new) = names.get(&old) {
                        observation.facts.insert(new.clone(), facts);
                    }
                }
                observation
                    .records
                    .splice(owner_index + 1..owner_index + 1, child.records);
                observation.refs.extend(child.refs);
                observation.ax_truncated |= child.ax_truncated;
                observation.refs_truncated |= child.refs_truncated;
                if let (Some(text), Some(child_text)) = (&mut observation.dom_text, child.dom_text)
                {
                    text.push_str(&format!(
                        "\n[frame {} origin {}]\n{}",
                        frame.frame_id, frame.origin, child_text
                    ));
                }
            }
            // Re-read browser identities, not just URLs: a frame can navigate
            // away and back to its original origin while a read is in flight.
            let after = self.frame_documents(context, deadline_ms)?;
            // No content was read from omitted frames. Their disappearance or
            // navigation cannot invalidate content from the retained documents.
            // Descendants of an omitted frame are also outside this observation.
            while let Some(frame) = after.iter().find(|frame| {
                !omitted_frames.contains(&frame.frame_id)
                    // A subtree may start inside an embedded document whose
                    // ancestors were not read. Its own identity still needs checking.
                    && frame.frame_id != main.frame_id
                    && frame
                        .parent_id
                        .as_ref()
                        .is_some_and(|parent| omitted_frames.contains(parent))
            }) {
                omitted_frames.insert(frame.frame_id.clone());
            }
            let retained_before: Vec<_> = before
                .iter()
                .filter(|frame| !omitted_frames.contains(&frame.frame_id))
                .collect();
            let retained_after: Vec<_> = after
                .iter()
                .filter(|frame| !omitted_frames.contains(&frame.frame_id))
                .collect();
            if retained_before != retained_after {
                let changed = retained_before
                    .iter()
                    .copied()
                    .find(|frame| !retained_after.contains(frame));
                let authorized_origin = changed
                    .map(|frame| frame.origin.clone())
                    .unwrap_or_else(|| main.origin.clone());
                let live_origin = changed
                    .and_then(|frame| after.iter().find(|live| live.frame_id == frame.frame_id))
                    .map(|frame| frame.origin.clone())
                    .unwrap_or_else(|| "null".into());
                return Err(NavigationDriveError::FrameChanged {
                    authorized_origin,
                    live_origin,
                });
            }
            Ok(observation)
        })();
        self.active_frame = None;
        self.read_frames = Some(allowed);
        result
    }
}

impl<IO: CdpPipeIo> CdpNavigationDriver<IO> {
    /// A parent renderer can hit the iframe owner rather than a node in the
    /// remote document. Follow that owner through its attached session before
    /// classifying or dispatching; the owner's origin is not the hit origin.
    pub(super) fn resolve_frame_point<C: NavigationClock>(
        &mut self,
        global: BrowserClickPosition,
        mut identity: BackendNodeIdentity,
        frames: &[FrameDocument],
        deadline: Instant,
        clock: &mut C,
    ) -> Result<(BackendNodeIdentity, FrameDocument, BrowserClickPosition), NavigationDriveError>
    {
        for _ in 0..128 {
            let frame = frames
                .iter()
                .find(|frame| frame.frame_id == identity.frame_id)
                .ok_or(NavigationDriveError::CdpFailure)?;
            let mut remote = None;
            for child in frames.iter().filter(|child| {
                child.parent_id.as_ref() == Some(&frame.frame_id)
                    && child.session_id != frame.session_id
            }) {
                let owner = self.command(
                    "DOM.getFrameOwner",
                    Some(
                        serde_json::json!({"frameId":child.frame_id})
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                    Some(frame.session_id.clone()),
                    deadline,
                    None,
                    clock,
                )?;
                if owner.get("backendNodeId").and_then(Value::as_u64)
                    == Some(identity.backend_node_id)
                {
                    if let Some(local) =
                        self.point_in_frame_session(global, child, frames, deadline, clock)?
                    {
                        remote = Some((child, local));
                    }
                    break;
                }
            }
            let Some((child, local)) = remote else {
                let local = self
                    .point_in_frame_session(global, frame, frames, deadline, clock)?
                    .ok_or(NavigationDriveError::CdpFailure)?;
                return Ok((identity, frame.clone(), local));
            };
            let visual = self.read_css_visual_viewport(&child.session_id, deadline, clock)?;
            let params = document_hit_params(local, visual)?;
            let hit = self.command(
                "DOM.getNodeForLocation",
                Some(params),
                Some(child.session_id.clone()),
                deadline,
                None,
                clock,
            )?;
            identity.frame_id = required_result_string(&hit, "frameId")?;
            identity.backend_node_id = hit
                .get("backendNodeId")
                .and_then(Value::as_u64)
                .filter(|id| *id > 0)
                .ok_or(NavigationDriveError::CdpFailure)?;
        }
        Err(NavigationDriveError::CdpFailure)
    }

    fn point_in_frame_session<C: NavigationClock>(
        &mut self,
        global: BrowserClickPosition,
        frame: &FrameDocument,
        frames: &[FrameDocument],
        deadline: Instant,
        clock: &mut C,
    ) -> Result<Option<BrowserClickPosition>, NavigationDriveError> {
        let mut chain = vec![frame];
        let mut seen = HashSet::from([frame.frame_id.as_str()]);
        while let Some(parent) = chain.last().and_then(|frame| frame.parent_id.as_ref()) {
            let parent = frames
                .iter()
                .find(|frame| &frame.frame_id == parent)
                .ok_or(NavigationDriveError::CdpFailure)?;
            if !seen.insert(parent.frame_id.as_str()) {
                return Err(NavigationDriveError::CdpFailure);
            }
            chain.push(parent);
        }
        chain.reverse();
        let mut point = global;
        for pair in chain.windows(2) {
            let (parent, child) = (pair[0], pair[1]);
            if parent.session_id == child.session_id {
                continue;
            }
            let owner = self.command(
                "DOM.getFrameOwner",
                Some(
                    serde_json::json!({"frameId":child.frame_id})
                        .as_object()
                        .unwrap()
                        .clone(),
                ),
                Some(parent.session_id.clone()),
                deadline,
                None,
                clock,
            )?;
            let backend = owner
                .get("backendNodeId")
                .and_then(Value::as_u64)
                .ok_or(NavigationDriveError::CdpFailure)?;
            let (quad, viewport) = self.frame_owner_geometry(parent, backend, deadline, clock)?;
            let Some(local) = frame_local_point(point, quad, viewport)? else {
                return Ok(None);
            };
            point = local;
        }
        Ok(Some(point))
    }
}

fn frame_local_point(
    point: BrowserClickPosition,
    quad: Quad,
    viewport: crate::coordinate::InputRect,
) -> Result<Option<BrowserClickPosition>, NavigationDriveError> {
    let [a, b, c, d] = quad.points;
    if !quad
        .points
        .iter()
        .all(|(x, y)| x.is_finite() && y.is_finite())
        || (c.0 - (b.0 + d.0 - a.0)).abs() > 0.05
        || (c.1 - (b.1 + d.1 - a.1)).abs() > 0.05
    {
        // A perspective quad does not have this affine inverse. Refuse instead
        // of classifying a point in a different document from the input point.
        return Err(NavigationDriveError::CdpFailure);
    }
    let (ux, uy, vx, vy) = (b.0 - a.0, b.1 - a.1, d.0 - a.0, d.1 - a.1);
    let determinant = ux * vy - uy * vx;
    if determinant.abs() < 1e-9 {
        return Err(NavigationDriveError::CdpFailure);
    }
    let (dx, dy) = (point.x_css - a.0, point.y_css - a.1);
    let u = (dx * vy - dy * vx) / determinant;
    let v = (ux * dy - uy * dx) / determinant;
    if !(0.0..=1.0).contains(&u) || !(0.0..=1.0).contains(&v) {
        return Ok(None);
    }
    Ok(Some(BrowserClickPosition {
        x_css: viewport.x_input_css + u * viewport.width_input_css,
        y_css: viewport.y_input_css + v * viewport.height_input_css,
    }))
}

impl<IO: CdpPipeIo> CdpNavigationDriver<IO> {
    fn frame_owner_geometry<C: NavigationClock>(
        &mut self,
        parent: &FrameDocument,
        backend: u64,
        deadline: Instant,
        clock: &mut C,
    ) -> Result<(Quad, crate::coordinate::InputRect), NavigationDriveError> {
        let model = self.command(
            "DOM.getBoxModel",
            Some(
                serde_json::json!({"backendNodeId":backend})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
            Some(parent.session_id.clone()),
            deadline,
            None,
            clock,
        )?;
        let content = model
            .get("model")
            .and_then(|value| value.get("content"))
            .cloned()
            .ok_or(NavigationDriveError::CdpFailure)?;
        let quads =
            required_content_quads(serde_json::json!({"quads":[content]}).as_object().unwrap())?;
        // Page.getLayoutMetrics in an OOPIF reports the top viewport, and
        // getContentQuads on an iframe includes its border. Get its actual
        // content dimensions from native computed style in an isolated world,
        // where page scripts cannot replace the DOM getters or prototypes.
        let world = self.command("Page.createIsolatedWorld", Some(serde_json::json!({"frameId":parent.frame_id,"worldName":"cortexkit-frame-geometry"}).as_object().unwrap().clone()), Some(parent.session_id.clone()), deadline, None, clock)?;
        let context = world
            .get("executionContextId")
            .and_then(Value::as_u64)
            .ok_or(NavigationDriveError::CdpFailure)?;
        let object = self.command(
            "DOM.resolveNode",
            Some(
                serde_json::json!({"backendNodeId":backend,"executionContextId":context})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
            Some(parent.session_id.clone()),
            deadline,
            None,
            clock,
        )?;
        let object_id = object
            .get("object")
            .and_then(|value| value.get("objectId"))
            .and_then(Value::as_str)
            .ok_or(NavigationDriveError::CdpFailure)?;
        let function = "function(){const s=getComputedStyle(this);let w=parseFloat(s.width),h=parseFloat(s.height);if(s.boxSizing==='border-box'){w-=parseFloat(s.borderLeftWidth)+parseFloat(s.borderRightWidth)+parseFloat(s.paddingLeft)+parseFloat(s.paddingRight);h-=parseFloat(s.borderTopWidth)+parseFloat(s.borderBottomWidth)+parseFloat(s.paddingTop)+parseFloat(s.paddingBottom);}return {width:w,height:h};}";
        let dimensions = self.command("Runtime.callFunctionOn", Some(serde_json::json!({"objectId":object_id,"functionDeclaration":function,"returnByValue":true}).as_object().unwrap().clone()), Some(parent.session_id.clone()), deadline, None, clock);
        let _ = self.command(
            "Runtime.releaseObject",
            Some(
                serde_json::json!({"objectId":object_id})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
            Some(parent.session_id.clone()),
            deadline,
            None,
            clock,
        );
        let dimensions = dimensions?;
        let width = dimensions
            .get("result")
            .and_then(|value| value.pointer("/value/width"))
            .and_then(Value::as_f64)
            .filter(|v| v.is_finite() && *v > 0.)
            .ok_or(NavigationDriveError::CdpFailure)?;
        let height = dimensions
            .get("result")
            .and_then(|value| value.pointer("/value/height"))
            .and_then(Value::as_f64)
            .filter(|v| v.is_finite() && *v > 0.)
            .ok_or(NavigationDriveError::CdpFailure)?;
        let quad = quads
            .first()
            .copied()
            .ok_or(NavigationDriveError::CdpFailure)?;
        Ok((
            quad,
            crate::coordinate::InputRect::new(0., 0., width, height),
        ))
    }

    pub(super) fn frame_global_point<C: NavigationClock>(
        &mut self,
        mut point: BrowserClickPosition,
        frame: &FrameDocument,
        frames: &[FrameDocument],
        deadline: Instant,
        clock: &mut C,
    ) -> Result<BrowserClickPosition, NavigationDriveError> {
        let mut child = frame;
        let mut seen = HashSet::new();
        while let Some(parent) = child.parent_id.as_ref() {
            if !seen.insert(child.frame_id.as_str()) {
                return Err(NavigationDriveError::CdpFailure);
            }
            let parent = frames
                .iter()
                .find(|frame| &frame.frame_id == parent)
                .ok_or(NavigationDriveError::CdpFailure)?;
            if child.session_id != parent.session_id {
                let owner = self.command(
                    "DOM.getFrameOwner",
                    Some(
                        serde_json::json!({"frameId":child.frame_id})
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                    Some(parent.session_id.clone()),
                    deadline,
                    None,
                    clock,
                )?;
                let backend = owner
                    .get("backendNodeId")
                    .and_then(Value::as_u64)
                    .ok_or(NavigationDriveError::CdpFailure)?;
                let (quad, viewport) =
                    self.frame_owner_geometry(parent, backend, deadline, clock)?;
                frame_local_point(
                    BrowserClickPosition {
                        x_css: quad.points[0].0,
                        y_css: quad.points[0].1,
                    },
                    quad,
                    viewport,
                )?;
                let u = point.x_css / viewport.width_input_css;
                let v = point.y_css / viewport.height_input_css;
                if !(0.0..=1.0).contains(&u) || !(0.0..=1.0).contains(&v) {
                    return Err(NavigationDriveError::CdpFailure);
                }
                let [a, b, _, d] = quad.points;
                point = BrowserClickPosition {
                    x_css: a.0 + (b.0 - a.0) * u + (d.0 - a.0) * v,
                    y_css: a.1 + (b.1 - a.1) * u + (d.1 - a.1) * v,
                };
            }
            child = parent;
        }
        Ok(point)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io;
    struct FixturePipe {
        responses: VecDeque<Vec<u8>>,
        move_during_read: bool,
        changed: bool,
        inputs: Vec<(String, f64, f64)>,
        requests: Vec<Value>,
        huge_page: bool,
    }
    fn ax(
        id: &str,
        backend: u64,
        role: &str,
        name: &str,
        children: Vec<&str>,
        frame: Option<&str>,
    ) -> Value {
        let mut node = json!({"nodeId":id,"backendDOMNodeId":backend,"ignored":false,"role":{"value":role},"name":{"value":name},"childIds":children});
        if let Some(frame) = frame {
            node["frameId"] = json!(frame);
        }
        node
    }
    fn dom(id: u64, parent: u64, name: &str, attrs: Vec<&str>) -> Value {
        json!({"nodeId":id,"backendNodeId":id,"nodeType":if name == "#document" {9} else {1},"parentId":parent,"localName":name,"attributes":attrs})
    }
    impl CdpPipeIo for FixturePipe {
        fn write_frame(&mut self, bytes: &[u8]) -> io::Result<()> {
            let request: Value = serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap();
            let session = request["sessionId"].as_str().unwrap_or("");
            let method = request["method"].as_str().unwrap();
            let cross = session == "cross-session";
            self.requests.push(request.clone());
            if method == "Input.dispatchMouseEvent" {
                self.inputs.push((
                    session.into(),
                    request["params"]["x"].as_f64().unwrap(),
                    request["params"]["y"].as_f64().unwrap(),
                ));
            }
            if self.move_during_read
                && cross
                && matches!(
                    method,
                    "Accessibility.getChildAXNodes" | "Accessibility.getPartialAXTree"
                )
            {
                self.changed = true;
            }
            let result = match method {
                "Target.createTarget" => json!({"targetId":"target"}),
                "Target.attachToTarget" => json!({"sessionId":"main-session"}),
                "Target.setAutoAttach" if !cross => {
                    let event = json!({"method":"Target.attachedToTarget","sessionId":"main-session","params":{"sessionId":"cross-session","targetInfo":{"targetId":"cross","type":"iframe"}}});
                    let mut bytes = serde_json::to_vec(&event).unwrap();
                    bytes.push(0);
                    self.responses.push_back(bytes);
                    json!({})
                }
                "Page.getFrameTree" if cross => {
                    json!({"frameTree":{"frame":{"id":"cross","parentId":"main","url":"http://localhost:9001/payment","securityOrigin":"http://localhost:9001","loaderId":if self.changed { "replacement-loader" } else { "cross-loader" }}}})
                }
                "Page.getFrameTree" => {
                    json!({"frameTree":{"frame":{"id":"main","url":"http://127.0.0.1:9000/","securityOrigin":"http://127.0.0.1:9000","loaderId":"main-loader"},"childFrames":[{"frame":{"id":"same","url":"http://127.0.0.1:9000/same","securityOrigin":"http://127.0.0.1:9000","loaderId":"same-loader"}}]}})
                }
                "Accessibility.getRootAXNode" => {
                    let frame = request["params"]["frameId"].as_str().unwrap_or("main");
                    let (id, backend, children) = match frame {
                        "same" => ("same-root", 20, vec!["same-button"]),
                        "cross" => ("cross-root", 30, vec!["card", "pay"]),
                        _ => ("main-root", 1, vec!["same-owner", "cross-owner"]),
                    };
                    let mut root = ax(id, backend, "RootWebArea", "", children, Some(frame));
                    if self.huge_page && frame == "main" {
                        root["childIds"] =
                            json!((0..20_000).map(|n| format!("row-{n}")).collect::<Vec<_>>());
                    }
                    json!({"node":root})
                }
                "Accessibility.getPartialAXTree" => {
                    assert_eq!(request["params"]["fetchRelatives"], false);
                    let node = match request["params"]["backendNodeId"].as_u64().unwrap() {
                        21 => ax("same-button", 21, "button", "Same button", vec![], None),
                        32 => {
                            let mut card = ax("card", 32, "textbox", "Card number", vec![], None);
                            card["value"] = json!({"value":"4111111111111111"});
                            card
                        }
                        11 => ax("cross-owner", 11, "Iframe", "Payment frame", vec![], None),
                        20_009 => ax("row-19999", 20_009, "row", "Event 19999", vec![], None),
                        _ => panic!("unexpected subtree identity"),
                    };
                    json!({"nodes":[node]})
                }
                "Accessibility.getChildAXNodes" => {
                    let nodes = match request["params"]["id"].as_str().unwrap() {
                        "same-root" => {
                            vec![ax("same-button", 21, "button", "Same button", vec![], None)]
                        }
                        "cross-root" => vec![
                            ax("card", 32, "textbox", "Card number", vec![], None),
                            ax("pay", 33, "button", "Pay", vec![], None),
                        ],
                        _ => vec![
                            ax("same-owner", 10, "Iframe", "Same frame", vec![], None),
                            ax("cross-owner", 11, "Iframe", "Payment frame", vec![], None),
                        ],
                    };
                    json!({"nodes":nodes})
                }
                "DOM.getFrameOwner" => {
                    json!({"backendNodeId":if request["params"]["frameId"] == "same" {10} else {11}})
                }
                "DOM.getNodeForLocation" => {
                    json!({"backendNodeId":if cross {33} else {11},"frameId":if cross {"cross"} else {"main"}})
                }
                "DOM.getContentQuads" => json!({"quads":[[320.,0.,620.,0.,620.,100.,320.,100.]]}),
                "DOM.getBoxModel" => {
                    json!({"model":{"content":[320.,0.,620.,0.,620.,100.,320.,100.]}})
                }
                "Page.createIsolatedWorld" => json!({"executionContextId":7}),
                "DOM.resolveNode" => {
                    json!({"object":{"objectId":if request["params"]["executionContextId"] == 7 { "native-owner" } else { "page-owner" }}})
                }
                "Runtime.callFunctionOn" => {
                    let native = request["params"]["objectId"] == "native-owner";
                    json!({"result":{"value":{"width":if native {300.} else {1.},"height":if native {100.} else {1.}}}})
                }
                "Page.getLayoutMetrics" => {
                    json!({"cssVisualViewport":{"offsetX":0.,"offsetY":0.,"pageX":0.,"pageY":0.,"clientWidth":if cross {300.} else {800.},"clientHeight":if cross {100.} else {600.},"scale":1.}})
                }
                "DOM.getFlattenedDocument" if cross => {
                    json!({"nodes":[dom(30,0,"#document",vec![]),dom(31,30,"form",vec!["id","payment"]),dom(32,31,"input",vec!["autocomplete","cc-number"]),dom(33,31,"button",vec!["type","submit"])]})
                }
                "DOM.getFlattenedDocument" => {
                    json!({"nodes":[dom(1,0,"#document",vec![]),dom(10,1,"iframe",vec![]),dom(11,1,"iframe",vec![]),dom(20,10,"#document",vec![]),dom(21,20,"button",vec!["type","button"])]})
                }
                "DOM.getOuterHTML" => {
                    json!({"outerHTML":if cross {"<input autocomplete='cc-number'>"} else {"<button>Same button</button>"}})
                }
                "DOM.pushNodesByBackendIdsToFrontend" => {
                    json!({"nodeIds": request["params"]["backendNodeIds"]})
                }
                "DOM.getDocument" => json!({"root":{"nodeId":1}}),
                "DOM.querySelector" => json!({"nodeId": 100}),
                _ => json!({}),
            };
            let mut response = json!({"id":request["id"],"result":result});
            if !session.is_empty() {
                response["sessionId"] = json!(session);
            }
            let mut bytes = serde_json::to_vec(&response).unwrap();
            bytes.push(0);
            self.responses.push_back(bytes);
            Ok(())
        }
        fn read(&mut self, output: &mut [u8]) -> io::Result<PipeRead> {
            let Some(mut bytes) = self.responses.pop_front() else {
                return Ok(PipeRead::WouldBlock);
            };
            if bytes.len() > output.len() {
                let remainder = bytes.split_off(output.len());
                self.responses.push_front(remainder);
            }
            output[..bytes.len()].copy_from_slice(&bytes);
            Ok(PipeRead::Bytes(bytes.len()))
        }
    }
    fn fixture() -> (CdpNavigationDriver<FixturePipe>, Vec<FrameDocument>) {
        let mut driver = CdpNavigationDriver::new(
            FixturePipe {
                responses: VecDeque::new(),
                move_during_read: false,
                changed: false,
                inputs: Vec::new(),
                requests: Vec::new(),
                huge_page: false,
            },
            CdpTransport::new(),
            CdpFrameDecoder::default(),
        );
        let frames = driver.frame_documents("isolated-fixture", 1000).unwrap();
        assert_eq!(frames.len(), 3);
        (driver, frames)
    }

    fn reference(frame: &FrameDocument, backend: u64) -> RefRecord {
        RefRecord {
            captured: SnapshotRef::new("e1", "row", "", 0).unwrap(),
            frame_path: vec![frame.frame_id.clone()],
            backend_identity: Some(
                BackendNodeIdentity::new("target", &frame.frame_id, backend).unwrap(),
            ),
            frame_document: Some(frame.clone()),
            raw_role: None,
            raw_name: None,
            classification: Err(ClassificationUnavailable::NotCaptured),
        }
    }

    #[test]
    fn zoom_reads_a_late_row_without_walking_the_twenty_thousand_row_page() {
        let (mut driver, frames) = fixture();
        driver.pipe.huge_page = true;
        driver.set_read_frames(frames.clone());
        let main = frames.iter().find(|f| f.frame_id == "main").unwrap();
        let full = driver
            .snapshot_classified(
                "isolated-fixture",
                SnapshotKind::Actionable,
                7,
                &main.url,
                1000,
            )
            .unwrap();
        assert!(full.ax_truncated);
        assert!(!full.records.iter().any(|r| r.name == "Event 19999"));
        driver.pipe.requests.clear();
        let zoom = driver
            .snapshot_subtree_classified(
                "isolated-fixture",
                SnapshotKind::Actionable,
                &reference(main, 20_009),
                7,
                &main.url,
                1000,
            )
            .unwrap();
        assert_eq!(zoom.records.len(), 1);
        assert_eq!(zoom.records[0].name, "Event 19999");
        assert!(!zoom.ax_truncated);
        assert!(!driver
            .pipe
            .requests
            .iter()
            .any(|r| r["method"] == "Accessibility.getRootAXNode"));
        let partial: Vec<_> = driver
            .pipe
            .requests
            .iter()
            .filter(|r| r["method"] == "Accessibility.getPartialAXTree")
            .collect();
        assert_eq!(partial.len(), 1);
        assert_eq!(partial[0]["sessionId"], "main-session");
        assert_eq!(partial[0]["params"]["backendNodeId"], 20_009);
    }

    #[test]
    fn zoom_embedded_element_uses_its_session_and_fresh_payment_masking() {
        let (mut driver, frames) = fixture();
        driver.set_read_frames(frames.clone());
        let cross = frames.iter().find(|f| f.frame_id == "cross").unwrap();
        driver.pipe.requests.clear();
        let zoom = driver
            .snapshot_subtree_classified(
                "isolated-fixture",
                SnapshotKind::Actionable,
                &reference(cross, 32),
                7,
                &cross.url,
                1000,
            )
            .unwrap();
        assert_eq!(zoom.records.len(), 1);
        assert_eq!(zoom.refs[0].frame_document.as_ref(), Some(cross));
        let classification = zoom.refs[0].classification.as_ref().unwrap();
        assert_eq!(classification.current_top_level_origin, cross.origin);
        assert!(classification
            .target_autocomplete_tokens
            .iter()
            .any(|t| t == "cc-number"));
        assert_eq!(zoom.facts["e1"].credential, Some(true));
        let text = state_text::render(&state_text::RenderInput {
            records: &zoom.records,
            facts: &zoom.facts,
            filters: &state_text::Filters::default(),
            page_url: &cross.url,
            snapshot_id: "0123456789abcdef0123456789abcdef",
            zoom: Some(state_text::Zoom {
                requested: "e1",
                target: Some("e1"),
            }),
            max_bytes: 65536,
        })
        .text;
        assert!(text.contains("Card number"));
        assert!(!text.contains("4111111111111111"));
        assert!(driver
            .pipe
            .requests
            .iter()
            .filter(|r| r["method"].as_str().unwrap().starts_with("Accessibility."))
            .all(|r| r["sessionId"] == "cross-session"));
    }

    #[test]
    fn zoom_withheld_embedded_element_never_reads_its_subtree() {
        let (mut driver, frames) = fixture();
        let cross = frames.iter().find(|f| f.frame_id == "cross").unwrap();
        for withheld_frame in ["cross", "main"] {
            driver.set_read_frames(
                frames
                    .iter()
                    .filter(|f| f.frame_id != withheld_frame)
                    .cloned()
                    .collect(),
            );
            driver.pipe.requests.clear();
            let zoom = driver
                .snapshot_subtree_classified(
                    "isolated-fixture",
                    SnapshotKind::Actionable,
                    &reference(cross, 32),
                    7,
                    &cross.url,
                    1000,
                )
                .unwrap();
            assert!(!zoom.records.iter().any(|r| r.name == "Card number"));
            assert!(!driver
                .pipe
                .requests
                .iter()
                .any(|r| r["method"] == "Accessibility.getPartialAXTree"));
            assert!(!driver
                .pipe
                .requests
                .iter()
                .any(|r| r["sessionId"] == "cross-session"
                    && r["method"].as_str().unwrap().starts_with("Accessibility.")));
        }
    }

    #[test]
    fn zoom_embedded_frame_navigation_during_read_discards_capture() {
        let (mut driver, frames) = fixture();
        let cross = frames.iter().find(|f| f.frame_id == "cross").unwrap();
        driver.set_read_frames(frames.clone());
        driver.pipe.move_during_read = true;
        assert!(matches!(
            driver.snapshot_subtree_classified(
                "isolated-fixture",
                SnapshotKind::Actionable,
                &reference(cross, 32),
                7,
                &cross.url,
                1000
            ),
            Err(NavigationDriveError::FrameChanged { .. })
        ));
    }

    #[test]
    fn zoom_iframe_owner_keeps_only_its_permitted_embedded_contents() {
        let (mut driver, frames) = fixture();
        let main = frames.iter().find(|f| f.frame_id == "main").unwrap();
        driver.set_read_frames(frames.clone());
        let zoom = driver
            .snapshot_subtree_classified(
                "isolated-fixture",
                SnapshotKind::Actionable,
                &reference(main, 11),
                7,
                &main.url,
                1000,
            )
            .unwrap();
        assert!(zoom.records.iter().any(|r| r.name == "Card number"));
        assert!(!zoom.records.iter().any(|r| r.name == "Same button"));
        assert!(!zoom.ax_truncated);
    }
    #[test]
    fn stable_refs_frame_revision_also_moves_on_same_document_events() {
        let (mut driver, _) = fixture();
        let session = driver.attachment.as_ref().unwrap().session_id.clone();
        for (method, params, expected) in [
            (
                "Page.navigatedWithinDocument",
                json!({"frameId":"same","url":"http://127.0.0.1:9000/frame#fragment"}),
                1,
            ),
            (
                "Page.frameNavigated",
                json!({"frame":{"id":"same","loaderId":"new-loader"}}),
                2,
            ),
        ] {
            let raw = json!({"method":method,"sessionId":session,"params":params});
            driver.observe_frame_session(&CdpEvent {
                method: method.into(),
                params: raw["params"].as_object().cloned(),
                session_id: Some(session.clone()),
                raw,
            });
            assert_eq!(driver.frame_revisions["same"], expected);
        }
    }

    #[test]
    fn stable_refs_frame_url_change_keeps_loader_session_origin_binding() {
        let (mut driver, frames) = fixture();
        let mut previous = frames
            .iter()
            .find(|f| f.frame_id == "same")
            .unwrap()
            .clone();
        previous.url.push_str("#old");
        previous.navigation_revision += 10;
        assert!(driver
            .prepare_frame("isolated-fixture", &previous, 1000)
            .unwrap());
        assert_ne!(driver.active_frame.as_ref().unwrap().url, previous.url);
        let mut different_origin = previous.clone();
        different_origin.origin = "https://other.example".into();
        assert!(!driver
            .prepare_frame("isolated-fixture", &different_origin, 1000)
            .unwrap());
        previous.loader_id = "another-document".into();
        assert!(!driver
            .prepare_frame("isolated-fixture", &previous, 1000)
            .unwrap());
    }

    #[test]
    fn oopif_point_walk_classifies_and_dispatches_in_hit_frame() {
        let (mut driver, _) = fixture();
        let position = BrowserClickPosition {
            x_css: 360.,
            y_css: 25.,
        };
        let record = driver
            .classify_point(
                "isolated-fixture",
                position,
                7,
                "http://127.0.0.1:9000/",
                1000,
            )
            .unwrap()
            .unwrap();
        assert!(record.financial && record.required_tier == 4);
        assert_eq!(record.current_top_level_origin, "http://localhost:9001");
        assert_eq!(
            record.node_identity,
            BackendNodeIdentity::new("target", "cross", 33)
                .unwrap()
                .digest()
        );
        let frame = driver.point_frame_document().unwrap();
        assert!(driver
            .prepare_frame("isolated-fixture", &frame, 1000)
            .unwrap());
        let outcome = driver
            .click_point_classified(
                "isolated-fixture",
                position,
                7,
                &frame.origin,
                &record,
                1000,
                &mut |_| {},
            )
            .unwrap();
        assert!(
            matches!(outcome, BrowserClickOutcome::Clicked { position: actual, .. } if actual == position)
        );
        assert_eq!(
            driver.pipe.inputs,
            vec![
                ("cross-session".into(), 40., 25.),
                ("cross-session".into(), 40., 25.)
            ]
        );
    }

    #[test]
    fn blank_and_srcdoc_inherit_creator_but_sandbox_opaque_does_not() {
        let (driver, _) = fixture();
        let tree = json!({"frame":{"id":"main","url":"http://127.0.0.1:9000/","securityOrigin":"http://127.0.0.1:9000","loaderId":"main-loader"},"childFrames":[
            {"frame":{"id":"blank","url":"about:blank","loaderId":"blank-loader"}},
            {"frame":{"id":"srcdoc","url":"about:srcdoc","loaderId":"srcdoc-loader"}},
            {"frame":{"id":"opaque","url":"about:blank","securityOrigin":"://","loaderId":"opaque-loader"}}
        ]});
        let mut frames = Vec::new();
        driver
            .collect_frame_documents(&tree, None, "main-session", &mut frames)
            .unwrap();
        assert_eq!(frames[1].origin, frames[0].origin);
        assert_eq!(frames[2].origin, frames[0].origin);
        assert_eq!(frames[3].origin, "null");
        assert!(classification::canonical_grant_origin(&frames[3].origin).is_none());
    }

    #[test]
    fn frame_local_point_maps_rotation_and_refuses_perspective() {
        let viewport = crate::coordinate::InputRect::new(0., 0., 300., 100.);
        let quad = Quad::new([(320., 0.), (320., 300.), (220., 300.), (220., 0.)]);
        let point = frame_local_point(
            BrowserClickPosition {
                x_css: 295.,
                y_css: 40.,
            },
            quad,
            viewport,
        )
        .unwrap()
        .unwrap();
        assert!((point.x_css - 40.).abs() < 1e-9 && (point.y_css - 25.).abs() < 1e-9);
        let perspective = Quad::new([(320., 0.), (320., 300.), (225., 300.), (220., 0.)]);
        assert_eq!(
            frame_local_point(
                BrowserClickPosition {
                    x_css: 295.,
                    y_css: 40.
                },
                perspective,
                viewport
            ),
            Err(NavigationDriveError::CdpFailure)
        );
    }

    #[test]
    fn frame_navigation_during_read_discards_capture() {
        let (mut driver, frames) = fixture();
        driver.set_read_frames(frames);
        driver.pipe.move_during_read = true;
        let result = driver.snapshot_classified(
            "isolated-fixture",
            SnapshotKind::Actionable,
            7,
            "http://127.0.0.1:9000/",
            1000,
        );
        assert!(
            matches!(result, Err(NavigationDriveError::FrameChanged { .. })),
            "{result:?}"
        );
    }

    #[test]
    fn granted_frame_walk_keeps_nested_refs_and_payment_classification() {
        let (mut driver, frames) = fixture();
        driver.set_read_frames(frames);
        let observation = driver
            .snapshot_classified(
                "isolated-fixture",
                SnapshotKind::Actionable,
                7,
                "http://127.0.0.1:9000/",
                1000,
            )
            .unwrap();
        for name in ["Same button", "Card number", "Pay"] {
            assert!(
                observation
                    .records
                    .iter()
                    .any(|n| n.name == name && n.depth >= 2),
                "missing nested {name}"
            );
        }
        let pay = observation
            .refs
            .iter()
            .find(|r| r.captured.name == "Pay")
            .unwrap();
        assert_eq!(
            pay.frame_document.as_ref().unwrap().session_id,
            "cross-session"
        );
        let record = pay.classification.as_ref().unwrap();
        assert!(record.financial && record.required_tier == 4);
        assert_eq!(record.current_top_level_origin, "http://localhost:9001");
        let references: HashSet<_> = observation
            .refs
            .iter()
            .map(|r| &r.captured.reference)
            .collect();
        assert_eq!(references.len(), observation.refs.len());
    }

    #[test]
    fn withheld_frames_leave_neither_owner_refs_nor_child_contents() {
        let (mut driver, frames) = fixture();
        driver.set_read_frames(
            frames
                .into_iter()
                .filter(|frame| frame.parent_id.is_none())
                .collect(),
        );
        let observation = driver
            .snapshot_classified(
                "isolated-fixture",
                SnapshotKind::Ax,
                7,
                "http://127.0.0.1:9000/",
                1000,
            )
            .unwrap();
        for name in ["Same button", "Card number", "Pay"] {
            assert!(!observation.records.iter().any(|record| record.name == name));
        }
        for name in ["Same frame", "Payment frame"] {
            let owner = observation
                .records
                .iter()
                .find(|record| record.name == name)
                .unwrap();
            assert!(owner.reference.is_none(), "{owner:?}");
        }
        assert!(!observation.refs.iter().any(|reference| reference
            .backend_identity
            .as_ref()
            .is_some_and(|identity| matches!(identity.backend_node_id, 10 | 11))));
    }
    #[test]
    fn top_page_capture_plan_includes_cross_origin_content() {
        let (mut driver, frames) = fixture();
        driver.set_read_frames(frames);
        for kind in [
            SnapshotKind::Actionable,
            SnapshotKind::Ax,
            SnapshotKind::DomFull,
        ] {
            let observation = driver
                .snapshot_classified("isolated-fixture", kind, 7, "http://127.0.0.1:9000/", 1000)
                .unwrap();
            assert!(observation.records.iter().any(|n| n.name == "Card number"));
            assert!(observation.records.iter().any(|n| n.name == "Pay"));
            assert!(observation.refs.iter().any(|r| r
                .frame_document
                .as_ref()
                .is_some_and(|f| f.frame_id == "cross")));
            if kind == SnapshotKind::DomFull {
                assert!(observation
                    .dom_text
                    .as_ref()
                    .is_some_and(|t| t.contains("cc-number")));
            }
        }
    }
    #[test]
    fn frame_ref_session_and_loader_changes_are_stale() {
        let (mut driver, frames) = fixture();
        let mut frame = frames
            .iter()
            .find(|f| f.frame_id == "cross")
            .unwrap()
            .clone();
        assert!(driver
            .prepare_frame("isolated-fixture", &frame, 1000)
            .unwrap());
        frame.loader_id = "replacement-loader".into();
        assert!(!driver
            .prepare_frame("isolated-fixture", &frame, 1000)
            .unwrap());
        frame.loader_id = "cross-loader".into();
        frame.session_id = "replacement-session".into();
        assert!(!driver
            .prepare_frame("isolated-fixture", &frame, 1000)
            .unwrap());
    }
}
