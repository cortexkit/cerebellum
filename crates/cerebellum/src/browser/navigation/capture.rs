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
        // Chrome answers queryAXTree without a role or name filter slowly or
        // not at all on large pages (5.6 s for a long GitHub issue's `main`),
        // so a zoom also reads the whole native tree (under a second there)
        // and projects it from the identity-verified root below; unrelated
        // nodes never enter the returned observation.
        let method = "Accessibility.getFullAXTree";
        let params = self.active_frame.as_ref().map_or_else(
            || serde_json::json!({}),
            |frame| serde_json::json!({"frameId":frame.frame_id}),
        );
        // A zoom's bulk attempt leaves the last second of the call to the
        // incremental subtree walk, so a page whose whole tree is too slow
        // still answers with a partial zoom. A fixed 2 s cap was too short
        // live: a long Wikipedia article's tree took longer than that under
        // load, and the zoom fell back to the slow walk.
        let deadline = if subtree.is_some() {
            deadline
                .checked_sub(Duration::from_millis(1000))
                .map_or(clock.now(), |reserved| reserved.max(clock.now()))
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
        // A tree larger than the capture limit is still walked from memory:
        // the walk below stops at MAX_AX_NODES and marks the observation
        // partial. Falling back to the incremental walker instead would refetch
        // the same prefix one node per round trip (seconds on a large page).
        let mut by_id: HashMap<String, RawAxNode> = HashMap::new();
        for node in nodes {
            // Chrome repeats some nodes verbatim in one getFullAXTree reply
            // (454 of 24,087 on a long Wikipedia article). An identical repeat
            // adds nothing; two different nodes under one id are not a tree.
            match by_id.get(&node.node_id) {
                Some(seen) if *seen == node => {}
                Some(_) => return None,
                None => {
                    by_id.insert(node.node_id.clone(), node);
                }
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

    /// A zoom reads the whole native tree and projects only the retained
    /// subtree: on a long GitHub issue an unfiltered queryAXTree took 5.6 s,
    /// which left the incremental fallback no time and the zoom almost empty.
    #[test]
    fn bulk_ax_zoom_reads_the_full_tree_and_projects_only_the_retained_subtree() {
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
                ax_node("root","RootWebArea","Settings", &["main","other"],1,None),
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
        assert!(!observation
            .records
            .iter()
            .any(|record| record.name == "Unrelated sibling"));
        assert_eq!(
            driver.pipe.writes[0]["method"],
            "Accessibility.getFullAXTree"
        );
        assert_eq!(driver.pipe.writes[0]["params"], json!({}));
    }

    /// A zoom's bulk read stops a second before the call's deadline, so a
    /// page whose whole tree is too slow still leaves the incremental walk
    /// time to answer.
    #[test]
    fn bulk_ax_zoom_leaves_the_incremental_walk_its_time() {
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
        assert!(clock.now() - started <= Duration::from_secs(5));
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

    /// Chrome can repeat a node verbatim in one bulk reply. Rejecting the
    /// whole reply for that sent a long Wikipedia article to the one-node-per-
    /// round-trip walk, which ran out of time with a fraction of the page.
    #[test]
    fn bulk_ax_tolerates_an_identical_repeat_but_not_a_conflicting_one() {
        let reply = |extra: Value| {
            [
                json!({"id":1,"sessionId":"session-own","result":{}}),
                json!({"id":2,"sessionId":"session-own","result":{"node":ax_node("root","RootWebArea","Settings", &["main"],1,Some("frame-own"))}}),
                json!({"id":3,"sessionId":"session-own","result":{"nodes":[
                    ax_node("root","RootWebArea","Settings", &["main"],1,Some("frame-own")),
                    ax_node("main","main","Protection", &["target"],2,None),
                    ax_node("target","checkbox","Require status checks", &[],3,None),
                    extra,
                ]}}),
            ]
        };
        let mut driver = bulk_driver(reply(ax_node(
            "target",
            "checkbox",
            "Require status checks",
            &[],
            3,
            None,
        )));
        let mut clock = FakeClock::new();
        let observation = driver
            .snapshot_for_test("route-own", SnapshotKind::Ax, 30_000, &mut clock)
            .unwrap();
        assert!(!observation.ax_truncated);
        assert_eq!(observation.records.len(), 3);

        let mut driver = bulk_driver(reply(ax_node(
            "target",
            "button",
            "A different node",
            &[],
            9,
            None,
        )));
        let observation = driver
            .snapshot_for_test("route-own", SnapshotKind::Ax, 30_000, &mut clock)
            .unwrap();
        assert!(
            driver
                .pipe
                .writes
                .iter()
                .any(|w| w["method"] == "Accessibility.getChildAXNodes"),
            "a conflicting repeat must fall back to the incremental walk"
        );
        assert!(observation.records.len() <= 3);
    }

    /// A real heavy page (a long GitHub issue) returns more AX nodes than the
    /// capture limit. Rejecting that reply made the incremental walker refetch
    /// the same prefix with about 800 `getChildAXNodes` round trips, which ran
    /// the snapshot into its deadline before classification could start.
    #[test]
    fn an_oversized_bulk_tree_is_walked_from_memory_up_to_the_capture_limit() {
        // 100 comment-like groups of 50 buttons: more nodes than the capture
        // limit, in the shape of a real page rather than one huge fan-out.
        let group_ids = (0..100).map(|g| format!("group-{g}")).collect::<Vec<_>>();
        let groups = group_ids.iter().map(String::as_str).collect::<Vec<_>>();
        let root = ax_node("root", "RootWebArea", "Huge", &groups, 1, Some("frame-own"));
        let mut nodes = vec![root.clone()];
        let mut backend = 2;
        for (g, group) in group_ids.iter().enumerate() {
            let items = (0..50).map(|i| format!("item-{g}-{i}")).collect::<Vec<_>>();
            let item_refs = items.iter().map(String::as_str).collect::<Vec<_>>();
            nodes.push(ax_node(
                group,
                "group",
                &format!("Group {g}"),
                &item_refs,
                backend,
                None,
            ));
            backend += 1;
            for item in &items {
                nodes.push(ax_node(item, "button", item, &[], backend, None));
                backend += 1;
            }
        }
        assert!(nodes.len() > MAX_AX_NODES);
        let mut driver = bulk_driver([
            json!({"id":1,"sessionId":"session-own","result":{}}),
            json!({"id":2,"sessionId":"session-own","result":{"node":root}}),
            json!({"id":3,"sessionId":"session-own","result":{"nodes":nodes}}),
        ]);
        let mut clock = FakeClock::new();
        let observation = driver
            .snapshot_for_test("route-own", SnapshotKind::Ax, 30_000, &mut clock)
            .unwrap();
        assert!(observation.ax_truncated && observation.refs_truncated);
        assert_eq!(observation.records.len(), MAX_AX_NODES);
        assert_eq!(observation.records[1].name, "Group 0");
        assert!(
            !driver
                .pipe
                .writes
                .iter()
                .any(|w| w["method"] == "Accessibility.getChildAXNodes"),
            "the bulk tree must not be refetched node by node"
        );
    }
}
