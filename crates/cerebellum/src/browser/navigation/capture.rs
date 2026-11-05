use super::*;

/// Wall-clock phases of the most recent frame capture, excluding wire encoding.
#[derive(Debug, Clone, Default)]
pub struct SnapshotTimings {
    pub ax_ms: u128,
    pub dom_read_ms: u128,
    pub classification_ms: u128,
    pub dom_facts_ms: u128,
    pub body_ms: u128,
}

impl<IO: CdpPipeIo> CdpNavigationDriver<IO> {
    pub(super) fn bulk_ax_capture<C: NavigationClock>(
        &mut self,
        attachment: &AttachedTarget,
        root: &RawAxNode,
        subtree: Option<&RefRecord>,
        deadline: Instant,
        clock: &mut C,
    ) -> Option<BrowserSnapshotObservation> {
        // Chrome can leave queryAXTree without a role/name query unanswered.
        // Use the native tree and project from the identity-verified root below;
        // unrelated nodes never enter the returned observation. A short attempt
        // leaves the incremental subtree walker its own fallback window.
        let method = "Accessibility.getFullAXTree";
        let params = self.active_frame.as_ref().map_or_else(
            || serde_json::json!({}),
            |frame| serde_json::json!({"frameId":frame.frame_id}),
        );
        let deadline = if subtree.is_some() {
            deadline.min(clock.now() + Duration::from_millis(2000))
        } else {
            deadline
        };
        // Bulk reads avoid a round trip per node on ordinary pages. Keep their
        // attempt short so unsupported, oversized or busy replies leave time for
        // the incremental walk to return its explicitly partial observation.
        let result = self
            .command(
                method,
                params.as_object().cloned(),
                Some(attachment.session_id.clone()),
                snapshot_step_deadline(deadline, true, clock.now()),
                None,
                clock,
            )
            .ok()?;
        let nodes = required_ax_nodes(&result).ok()?;
        if nodes.len() > MAX_AX_NODES {
            return None;
        }
        let mut by_id = HashMap::new();
        for node in nodes {
            if by_id.insert(node.node_id.clone(), node).is_some() {
                return None;
            }
        }
        let mut fresh_root = by_id.get(&root.node_id)?.clone();
        if fresh_root.backend_node_id != root.backend_node_id {
            return None;
        }
        fresh_root.frame_id = root.frame_id.clone();
        traverse_ax_tree(
            fresh_root,
            &attachment.target_id,
            MAX_AX_NODES,
            MAX_AX_DEPTH,
            |id, _| {
                by_id[id]
                    .child_ids
                    .iter()
                    .map(|child| {
                        by_id
                            .get(child)
                            .cloned()
                            .ok_or(NavigationDriveError::CdpFailure)
                    })
                    .collect()
            },
        )
        .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{attached_driver, ax_node, raw_node, FakeClock, FakePipe};
    use super::*;
    use serde_json::json;

    fn bulk_driver(frames: impl IntoIterator<Item = Value>) -> CdpNavigationDriver<FakePipe> {
        let mut driver = CdpNavigationDriver::new(
            FakePipe::with_frames(frames),
            CdpTransport::new(),
            CdpFrameDecoder::default(),
        );
        driver
            .identities
            .attach(Attachment {
                target_id: "target-own".into(),
                session_id: "session-own".into(),
                frame_ids: vec![],
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

    #[test]
    fn bulk_ax_snapshot_batches_complete_tree() {
        let mut driver = bulk_driver([
            json!({"id":1,"sessionId":"session-own","result":{}}),
            json!({"id":2,"sessionId":"session-own","result":{"node":ax_node("root","RootWebArea","Settings", &["main"],1,Some("frame-own"))}}),
            json!({"id":3,"sessionId":"session-own","result":{"nodes":[
                ax_node("root","RootWebArea","Settings", &["main"],1,Some("frame-own")),
                ax_node("main","main","Protection", &["target"],2,None),
                ax_node("target","checkbox","Require status checks", &[],3,None),
            ]}}),
        ]);
        let mut clock = FakeClock::new();
        let observation = driver
            .snapshot_for_test("route-own", SnapshotKind::Ax, 30_000, &mut clock)
            .unwrap();
        assert!(!observation.ax_truncated);
        assert_eq!(observation.records.len(), 3);
        assert_eq!(observation.records[2].name, "Require status checks");
        assert_eq!(driver.pipe.writes.len(), 3);
        assert_eq!(
            driver.pipe.writes[2]["method"],
            "Accessibility.getFullAXTree"
        );
    }

    #[test]
    fn live_chrome_regression_bulk_zoom_projects_only_the_retained_subtree() {
        let root = raw_node(
            "main",
            "main",
            "Protection",
            &["target"],
            2,
            Some("frame-own"),
        );
        let reference = RefRecord {
            frame_document: None,
            captured: SnapshotRef::new("e200", "main", "Protection", 0).unwrap(),
            frame_path: vec!["frame-own".into()],
            backend_identity: Some(BackendNodeIdentity::new("target-own", "frame-own", 2).unwrap()),
            raw_role: None,
            raw_name: None,
            classification: Err(ClassificationUnavailable::NotCaptured),
        };
        let mut driver =
            attached_driver([json!({"id":1,"sessionId":"session-own","result":{"nodes":[
                ax_node("main","main","Protection", &["target"],2,None),
                ax_node("target","checkbox","Require status checks", &[],3,None),
                ax_node("other","button","Unrelated sibling", &[],4,None),
            ]}})]);
        let attachment = driver.attachment.clone().unwrap();
        let mut clock = FakeClock::new();
        let deadline = clock.now() + Duration::from_secs(30);
        let observation = driver
            .bulk_ax_capture(&attachment, &root, Some(&reference), deadline, &mut clock)
            .unwrap();
        assert_eq!(observation.records.len(), 2);
        assert_eq!(
            driver.pipe.writes[0]["method"],
            "Accessibility.getFullAXTree"
        );
        assert_eq!(driver.pipe.writes[0]["params"], json!({}));
        assert!(!observation
            .records
            .iter()
            .any(|r| r.name == "Unrelated sibling"));
    }

    #[test]
    fn live_chrome_regression_bulk_zoom_leaves_incremental_time() {
        let root = raw_node("main", "main", "Main", &[], 2, Some("frame-own"));
        let reference = RefRecord {
            frame_document: None,
            captured: SnapshotRef::new("e1", "main", "Main", 0).unwrap(),
            frame_path: vec!["frame-own".into()],
            backend_identity: Some(BackendNodeIdentity::new("target-own", "frame-own", 2).unwrap()),
            raw_role: None,
            raw_name: None,
            classification: Err(ClassificationUnavailable::NotCaptured),
        };
        let mut driver = attached_driver([]);
        let attachment = driver.attachment.clone().unwrap();
        let mut clock = FakeClock::new();
        let started = clock.now();
        assert!(driver
            .bulk_ax_capture(
                &attachment,
                &root,
                Some(&reference),
                started + Duration::from_secs(6),
                &mut clock
            )
            .is_none());
        assert!(clock.now() - started <= Duration::from_secs(2));
        assert_eq!(driver.transport.pending_len(), 0);
    }

    #[test]
    fn bulk_ax_error_oversize_and_timeout_keep_incremental_partial_fallback() {
        let child_ids = (0..MAX_AX_NODES + 1)
            .map(|n| format!("child-{n}"))
            .collect::<Vec<_>>();
        let children = child_ids.iter().map(String::as_str).collect::<Vec<_>>();
        let oversized = (0..MAX_AX_NODES + 1)
            .map(|n| ax_node(&format!("n{n}"), "generic", "", &[], n as u64 + 2, None))
            .collect::<Vec<_>>();
        for bulk_reply in [
            Some(
                json!({"id":3,"sessionId":"session-own","error":{"code":-32601,"message":"unsupported"}}),
            ),
            Some(json!({"id":3,"sessionId":"session-own","result":{"nodes":oversized}})),
            None,
        ] {
            let replies = [
                Some(json!({"id":1,"sessionId":"session-own","result":{}})),
                Some(json!({"id":2,"sessionId":"session-own","result":{"node":ax_node("root","RootWebArea","Huge", &children,1,Some("frame-own"))}})),
                bulk_reply,
            ].into_iter().flatten();
            let mut driver = bulk_driver(replies);
            let mut clock = FakeClock::new();
            let start = clock.now();
            let observation = driver
                .snapshot_for_test("route-own", SnapshotKind::Ax, 30_000, &mut clock)
                .unwrap();
            assert!(observation.ax_truncated && observation.refs_truncated);
            assert_eq!(observation.records.len(), 1);
            assert_eq!(driver.pipe.writes.len(), 3);
            assert!(
                clock.now().duration_since(start)
                    <= Duration::from_millis(crate::budgets::CDP_STEP_MS)
            );
        }
    }
}
