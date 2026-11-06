use super::*;

// GitHub's rust-lang/rust issue 25860 peaked at 248 active navigation records.
// Leave over eight times that headroom, separate from live frame/session state.
const MAX_NAVIGATION_REQUEST_RECORDS: usize = 2_048;

/// High-water marks contain only sizes, never page content or identities.
#[derive(Debug, Default, Clone, Copy, serde::Serialize)]
pub struct ConnectionMetadata {
    pub live_records: usize,
    pub active_requests: usize,
    pub preserved_replies: usize,
    pub unresolved_dialogs: usize,
    pub abandoned_commands: usize,
    pub retained_bytes: usize,
}

impl<IO: CdpPipeIo> CdpNavigationDriver<IO> {
    pub(super) fn enforce_metadata_bounds(
        &mut self,
        tracker: Option<&Tracker>,
    ) -> Result<(), NavigationDriveError> {
        if !self.continuously_serviced {
            return Ok(());
        }
        if self.connection_reset_required {
            return Err(NavigationDriveError::ConnectorFailure);
        }
        let (pending, abandoned, transport_bytes) = self.transport.retained_metadata();
        let (requests, tracker_bytes) = tracker.map_or((0, 0), Tracker::retained_metadata);
        let frames = self.frame_revisions.len().max(self.frame_documents.len());
        let peer_records = self.document_peers.len() + self.private_peer_origins.len();
        let sessions = self
            .frame_sessions
            .values()
            .chain(self.configured_frame_sessions.iter())
            .chain(self.focus_emulated_sessions.iter())
            .chain(
                self.attachment
                    .iter()
                    .map(|attachment| &attachment.session_id),
            )
            .chain(
                self.verification
                    .iter()
                    .map(|verification| &verification.session_id),
            )
            .collect::<HashSet<_>>()
            .len();
        let replies = self.pending_responses.len();
        let strings = |a: &String, b: &String| 256 + a.capacity() + b.capacity();
        let frame_bytes = self
            .frame_documents
            .iter()
            .chain(self.read_frames.iter().flatten())
            .chain(self.active_frame.iter())
            .chain(self.point_frame.iter())
            .map(|f| {
                512 + f.frame_id.capacity()
                    + f.parent_id.as_ref().map_or(0, String::capacity)
                    + f.session_id.capacity()
                    + f.loader_id.capacity()
                    + f.url.capacity()
                    + f.origin.capacity()
            })
            .sum::<usize>();
        let bytes = transport_bytes
            + tracker_bytes
            + self.document_peers.capacity() * 128
            + self
                .document_peers
                .keys()
                .map(|(session, frame, loader)| {
                    256 + session.capacity() + frame.capacity() + loader.capacity()
                })
                .sum::<usize>()
            + self.private_peer_origins.capacity() * 64
            + self
                .private_peer_origins
                .iter()
                .map(|origin| 256 + origin.capacity())
                .sum::<usize>()
            + frame_bytes
            + self.identities.retained_bytes()
            + self.frame_documents.capacity()
                * std::mem::size_of::<crate::snapshot_store::FrameDocument>()
            + self.read_frames.as_ref().map_or(0, |frames| {
                frames.capacity() * std::mem::size_of::<crate::snapshot_store::FrameDocument>()
            })
            + self.pending_javascript_dialogs.capacity()
                * std::mem::size_of::<PendingJavaScriptDialog>()
            + self.frame_revisions.capacity() * 64
            + self.frame_sessions.capacity() * 96
            + self.frame_document_generations.capacity() * 64
            + self
                .frame_document_generations
                .keys()
                .map(|id| 256 + id.capacity())
                .sum::<usize>()
            + self.live_frame_parents.capacity() * 96
            + self.configured_frame_sessions.capacity() * 64
            + self.focus_emulated_sessions.capacity() * 64
            + self
                .live_frame_parents
                .iter()
                .map(|(k, v)| 256 + k.capacity() + v.as_ref().map_or(0, String::capacity))
                .sum::<usize>()
            + self
                .frame_revisions
                .keys()
                .map(|s| 256 + s.capacity())
                .sum::<usize>()
            + self
                .frame_sessions
                .iter()
                .map(|(a, b)| strings(a, b))
                .sum::<usize>()
            + self
                .configured_frame_sessions
                .iter()
                .chain(self.focus_emulated_sessions.iter())
                .map(|s| 256 + s.capacity())
                .sum::<usize>()
            + self
                .pending_javascript_dialogs
                .iter()
                .map(|d| 128 + d.session_id.capacity() + d.dialog_type.capacity())
                .sum::<usize>()
            + self
                .pending_responses
                .values()
                .map(|r| {
                    256 + r.session_id.as_ref().map_or(0, String::capacity)
                        + r.result
                            .as_ref()
                            .map_or(0, crate::cdp::retained_object_bytes)
                        + r.error
                            .as_ref()
                            .map_or(0, crate::cdp::retained_object_bytes)
                })
                .sum::<usize>()
            + self.attachment.as_ref().map_or(0, |a| {
                256 + a.context_key.capacity() + a.target_id.capacity() + a.session_id.capacity()
            });
        let peak = &mut self.metadata_high_water;
        peak.live_records = peak.live_records.max(frames + sessions + peer_records);
        peak.active_requests = peak.active_requests.max(requests);
        peak.preserved_replies = peak.preserved_replies.max(replies + pending);
        peak.unresolved_dialogs = peak
            .unresolved_dialogs
            .max(self.pending_javascript_dialogs.len());
        peak.abandoned_commands = peak.abandoned_commands.max(abandoned);
        peak.retained_bytes = peak.retained_bytes.max(bytes);
        // Capacity accounting includes conservative container overhead. Decoder
        // storage and the active snapshot payload have their separate message cap.
        if frames + sessions + peer_records > 256
            || requests > MAX_NAVIGATION_REQUEST_RECORDS
            || replies + pending > 16
            || abandoned > 1024
            || self.pending_javascript_dialogs.len() > 64
            || bytes > 4 * 1024 * 1024
        {
            // Remember that this connection needs a reset even after the
            // temporary foreground tracker is dropped. The idle owner must
            // still observe that overflow and close the session.
            self.connection_reset_required = true;
            return Err(NavigationDriveError::ConnectorFailure);
        }
        Ok(())
    }
}

impl<IO: CdpPipeIo> CdpNavigationDriver<IO> {
    pub(super) fn observe_live_frame(&mut self, event: &CdpEvent) {
        let Some(params) = event.params.as_ref() else {
            return;
        };
        let frame = params.get("frame").and_then(Value::as_object);
        let Some(id) = params
            .get("frameId")
            .and_then(Value::as_str)
            .or_else(|| frame?.get("id")?.as_str())
        else {
            return;
        };
        if !matches!(
            event.method.as_str(),
            "Page.frameNavigated" | "Page.frameDetached" | "Page.navigatedWithinDocument"
        ) {
            return;
        }
        let main = self.attachment.as_ref().is_some_and(|a| a.target_id == id);
        if event.method == "Page.navigatedWithinDocument" {
            self.frame_generation = self.frame_generation.saturating_add(1);
            self.frame_revisions
                .insert(id.to_owned(), self.frame_generation);
            if let Some(document) = self.frame_documents.iter_mut().find(|f| f.frame_id == id) {
                document.navigation_revision = self.frame_generation;
                if let Some(url) = params.get("url").and_then(Value::as_str) {
                    document.url = url.to_owned();
                    document.origin = document_origin(url).unwrap_or_default();
                }
            }
            self.read_frames = None;
            self.active_frame = None;
            self.point_frame = None;
            self.point_target = None;
            return;
        }
        let mut obsolete = HashSet::new();
        obsolete.insert(id.to_owned());
        if main && event.method == "Page.frameNavigated" {
            obsolete.extend(self.live_frame_parents.keys().cloned());
        } else {
            loop {
                let before = obsolete.len();
                for (child, parent) in &self.live_frame_parents {
                    if parent.as_ref().is_some_and(|p| obsolete.contains(p)) {
                        obsolete.insert(child.clone());
                    }
                }
                if before == obsolete.len() {
                    break;
                }
            }
        }
        self.live_frame_parents
            .retain(|key, _| !obsolete.contains(key));
        self.frame_revisions
            .retain(|key, _| !obsolete.contains(key));
        self.frame_document_generations
            .retain(|key, _| !obsolete.contains(key));
        self.frame_documents
            .retain(|f| !obsolete.contains(&f.frame_id));
        // Keep a response received before this commit only for its exact loader.
        // Origin history is not evicted: dropping a private sighting would turn
        // a later unknown-address document back into public browsing.
        // A renderer swap is not a document removal. Its response can already
        // have arrived in the parent session before the child target attaches.
        if event.method != "Page.frameDetached"
            || params.get("reason").and_then(Value::as_str) != Some("swap")
        {
            self.document_peers.retain(|(_, frame_id, loader), _| {
                !obsolete.contains(frame_id)
                    || frame_id == id
                        && event.method == "Page.frameNavigated"
                        && frame
                            .and_then(|f| f.get("loaderId"))
                            .and_then(Value::as_str)
                            == Some(loader.as_str())
            });
        }
        self.read_frames = None;
        self.active_frame = None;
        self.point_frame = None;
        self.point_target = None;
        self.frame_sessions.retain(|key, _| {
            !obsolete.contains(key) || key == id && event.method != "Page.frameDetached"
        });
        if event.method == "Page.frameDetached" {
            return;
        }
        self.frame_generation = self.frame_generation.saturating_add(1);
        self.frame_revisions
            .insert(id.to_owned(), self.frame_generation);
        self.frame_document_generations
            .insert(id.to_owned(), self.frame_generation);
        let parent = frame
            .and_then(|f| f.get("parentId"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        self.live_frame_parents
            .insert(id.to_owned(), parent.clone());
        if let Some(frame) = frame {
            if let (Some(loader), Some(url), Some(session)) = (
                frame.get("loaderId").and_then(Value::as_str),
                frame.get("url").and_then(Value::as_str),
                event.session_id.as_ref(),
            ) {
                self.frame_documents
                    .push(crate::snapshot_store::FrameDocument {
                        network: self.document_network(session, id, loader, url),
                        navigation_revision: self.frame_generation,
                        frame_id: id.to_owned(),
                        parent_id: parent,
                        session_id: session.clone(),
                        loader_id: loader.to_owned(),
                        url: url.to_owned(),
                        origin: document_origin(url).unwrap_or_default(),
                    });
            }
        }
    }
}

impl<IO: CdpPipeIo> CdpNavigationDriver<IO> {
    pub(super) fn enable_lifecycle_events<C: NavigationClock>(
        &mut self,
        deadline: Instant,
        clock: &mut C,
    ) -> Result<(), NavigationDriveError> {
        if self.lifecycle_events_enabled {
            return Ok(());
        }
        let session = self
            .attachment
            .as_ref()
            .ok_or(NavigationDriveError::Unavailable)?
            .session_id
            .clone();
        let mut params = Map::new();
        params.insert("enabled".into(), Value::Bool(true));
        self.command(
            "Page.setLifecycleEventsEnabled",
            Some(params),
            Some(session),
            deadline,
            None,
            clock,
        )?;
        self.lifecycle_events_enabled = true;
        Ok(())
    }
}
