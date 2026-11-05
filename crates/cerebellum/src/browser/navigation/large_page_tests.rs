use super::tests::{ax_node, FakeClock};
use super::*;
use std::io;

/// Replies follow methods rather than request numbers so the tests also cover
/// moving classification ahead of an expensive accessibility traversal.
struct ThreadPipe {
    nodes: Vec<Value>,
    dom: Value,
    reads: VecDeque<Vec<u8>>,
    dom_polls: usize,
    blocked: usize,
    stall_ads: bool,
}

impl CdpPipeIo for ThreadPipe {
    fn write_frame(&mut self, bytes: &[u8]) -> io::Result<()> {
        let request: Value = serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap();
        let result = match request["method"].as_str().unwrap() {
            "Accessibility.getRootAXNode" => serde_json::json!({"node": self.nodes[0]}),
            "Accessibility.getPartialAXTree" => serde_json::json!({"nodes": [self.nodes[0]]}),
            "Accessibility.getFullAXTree" | "Accessibility.queryAXTree" => {
                serde_json::json!({"nodes": self.nodes})
            }
            "Accessibility.getChildAXNodes" => {
                let id = request["params"]["id"].as_str().unwrap();
                if self.stall_ads && id.starts_with("ad") {
                    return Ok(());
                }
                let parent = self.nodes.iter().find(|node| node["nodeId"] == id).unwrap();
                let children = parent["childIds"].as_array().unwrap();
                serde_json::json!({"nodes": self.nodes.iter().filter(|node| children.contains(&node["nodeId"])).collect::<Vec<_>>()})
            }
            "DOM.getFlattenedDocument" => {
                self.blocked = self.dom_polls;
                self.dom.clone()
            }
            "Accessibility.enable" | "DOM.enable" => serde_json::json!({}),
            method => panic!("unexpected snapshot method: {method}"),
        };
        let mut reply = serde_json::to_vec(&serde_json::json!({
            "id": request["id"], "sessionId": request["sessionId"], "result": result,
        }))
        .unwrap();
        reply.push(0);
        self.reads.push_back(reply);
        Ok(())
    }

    fn read(&mut self, destination: &mut [u8]) -> io::Result<PipeRead> {
        if self.blocked > 0 {
            self.blocked -= 1;
            return Ok(PipeRead::WouldBlock);
        }
        let Some(mut bytes) = self.reads.pop_front() else {
            return Ok(PipeRead::WouldBlock);
        };
        if bytes.len() > destination.len() {
            self.reads.push_front(bytes.split_off(destination.len()));
        }
        destination[..bytes.len()].copy_from_slice(&bytes);
        Ok(PipeRead::Bytes(bytes.len()))
    }
}

fn thread_driver(nodes: Vec<Value>) -> CdpNavigationDriver<ThreadPipe> {
    let mut driver = CdpNavigationDriver::new(
        ThreadPipe {
            nodes,
            dom: serde_json::json!({"nodes":[
                {"nodeId":1,"backendNodeId":1,"nodeType":9,"localName":"#document"},
                {"nodeId":2,"backendNodeId":2,"parentId":1,"nodeType":1,"localName":"button","attributes":["type","button"]},
            ]}),
            reads: VecDeque::new(),
            dom_polls: 0,
            blocked: 0,
            stall_ads: false,
        },
        CdpTransport::new(),
        CdpFrameDecoder::default(),
    )
    .with_incremental_ax_snapshots();
    driver
        .identities
        .attach(Attachment {
            target_id: "target-own".into(),
            session_id: "session-own".into(),
            context_key: "route-own".into(),
            frame_ids: Vec::new(),
        })
        .unwrap();
    driver.attachment = Some(AttachedTarget {
        target_id: "target-own".into(),
        session_id: "session-own".into(),
        context_key: "route-own".into(),
    });
    driver
}

fn partial_thread() -> BrowserSnapshotObservation {
    let ids = (0..MAX_AX_NODES + 1)
        .map(|i| format!("reply{i}"))
        .collect::<Vec<_>>();
    let children = ids.iter().map(String::as_str).collect::<Vec<_>>();
    let mut driver = thread_driver(vec![
        ax_node(
            "root",
            "RootWebArea",
            "Thread",
            &["comments"],
            1,
            Some("frame-main"),
        ),
        ax_node("comments", "region", "Comments", &children, 2, None),
        ax_node("reply0", "button", "13 more replies", &[], 3, None),
    ]);
    driver
        .snapshot_with_clock(
            "route-own",
            SnapshotKind::Actionable,
            30_000,
            Some((7, "https://example.com/")),
            None,
            &[],
            &mut FakeClock::new(),
        )
        .unwrap()
}

fn route() -> crate::RouteIdentity {
    crate::RouteIdentity::from_accepted_bind(
        &subc_protocol::BindIdentity::new("test", "large-page"),
        &Some(subc_protocol::Principal::Direct),
        None,
    )
}

#[tokio::test]
async fn filtered_cut_capture_reports_unsearched_matches() {
    let observation = partial_thread();
    assert!(observation.ax_truncated && observation.refs_truncated);
    assert!(!observation
        .records
        .iter()
        .any(|r| r.name == "13 more replies"));
    let identity = route();
    let plane = crate::browser::BrowserPlane::new();
    plane.open_context(identity.clone()).await.unwrap();
    for text in ["more repl", "Comments"] {
        let (reply, _) = plane
            .retain_text_snapshot_inner(
                &identity,
                SnapshotKind::Actionable,
                &observation.records,
                None,
                observation.refs.clone(),
                &observation.facts,
                None,
                &state_text::Filters {
                    text: Some(text.into()),
                    roles: vec![],
                },
                30_000,
                observation.ax_truncated,
                observation.refs_truncated,
                None,
            )
            .await
            .unwrap();
        let text = reply["state_text"].as_str().unwrap();
        assert!(text.contains("Capture stopped early"), "{text}");
        assert!(
            text.contains("matches beyond the captured portion were not searched"),
            "{text}"
        );
        assert!(
            text.to_lowercase().contains("zoom") && text.contains("container ref"),
            "{text}"
        );
        assert!(
            !text.contains("No matches for the requested filters."),
            "{text}"
        );
        assert_eq!(reply["truncated"], true);
    }
}

#[tokio::test]
async fn zoomed_cut_capture_reports_missing_subtrees() {
    let observation = partial_thread();
    let identity = route();
    let plane = crate::browser::BrowserPlane::new();
    plane.open_context(identity.clone()).await.unwrap();
    for zoom in [None, Some("e2")] {
        let (reply, _) = plane
            .retain_text_snapshot_inner(
                &identity,
                SnapshotKind::Actionable,
                &observation.records,
                None,
                observation.refs.clone(),
                &observation.facts,
                zoom,
                &state_text::Filters::default(),
                30_000,
                observation.ax_truncated,
                observation.refs_truncated,
                None,
            )
            .await
            .unwrap();
        assert_eq!(reply["outcome"], "ok", "{reply}");
        let text = reply["state_text"].as_str().unwrap();
        assert!(
            text.contains("Capture stopped early") && text.contains("container ref"),
            "{text}"
        );
    }
}

#[test]
fn slow_dom_classification_uses_remaining_call_time_before_ax_children() {
    for stall_ads in [false, true] {
        let mut nodes = vec![
            ax_node(
                "root",
                "region",
                "Comments",
                &["reply", "ad1", "ad2", "ad3", "ad4", "ad5", "ad6"],
                1,
                Some("frame-main"),
            ),
            ax_node("reply", "button", "13 more replies", &[], 2, None),
        ];
        for i in 1..=6 {
            nodes.push(ax_node(
                &format!("ad{i}"),
                "Iframe",
                "Ad",
                if stall_ads { &["missing"] } else { &[] },
                i + 2,
                None,
            ));
        }
        let mut driver = thread_driver(nodes);
        driver.pipe.dom_polls = 8_000 / POLL_INTERVAL.as_millis() as usize;
        driver.pipe.stall_ads = stall_ads;
        let mut clock = FakeClock::new();
        let start = clock.now();
        let reference = RefRecord {
            captured: SnapshotRef::new("e1", "region", "Comments", 0).unwrap(),
            backend_identity: Some(
                BackendNodeIdentity::new("target-own", "frame-main", 1).unwrap(),
            ),
            frame_path: vec!["frame-main".into()],
            frame_document: None,
            raw_role: None,
            raw_name: None,
            classification: Err(ClassificationUnavailable::NotCaptured),
        };
        let observation = driver
            .snapshot_with_clock(
                "route-own",
                SnapshotKind::Actionable,
                30_000,
                Some((7, "https://example.com/")),
                Some(&reference),
                &[],
                &mut clock,
            )
            .unwrap();
        let reply = observation
            .refs
            .iter()
            .find(|r| r.captured.name == "13 more replies")
            .unwrap();
        assert!(
            reply.classification.is_ok(),
            "healthy slow DOM must classify the reply: {:?}",
            reply.classification
        );
        assert!(clock.now().duration_since(start) <= Duration::from_secs(30));
        if stall_ads {
            assert!(observation.ax_truncated && observation.refs_truncated);
        }
        assert_eq!(driver.transport.pending_len(), 0);
    }
}
