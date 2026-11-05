use super::tests::{ax_node, FakeClock};
use super::*;
use std::io;

/// Replies follow methods rather than request numbers so the tests also cover
/// phase ordering without coupling the peer to request numbers.
pub(super) struct ThreadPipe {
    nodes: Vec<Value>,
    dom: Value,
    reads: VecDeque<Vec<u8>>,
    dom_polls: usize,
    blocked: usize,
    pub(super) stall_ads: bool,
    pub(super) scoped: scoped_fixture::ScopedDom,
    fail_flattened: bool,
    pub(super) requests: Vec<Value>,
    pub(super) markup: Option<String>,
    frames: Vec<crate::snapshot_store::FrameDocument>,
}

impl CdpPipeIo for ThreadPipe {
    fn write_frame(&mut self, bytes: &[u8]) -> io::Result<()> {
        let request: Value = serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap();
        self.requests.push(request.clone());
        // The browser's frame-tree reply is independent of a timed-out
        // renderer DOM request; its late reply can still arrive first.
        if request["method"] == "Page.getFrameTree" {
            self.blocked = 0;
        }
        let result = match request["method"].as_str().unwrap() {
            _ if scoped_fixture::ScopedDom::handles(&request) => {
                self.scoped.answer(&request, &self.dom).unwrap()
            }
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
                if self.fail_flattened {
                    serde_json::json!({})
                } else {
                    self.dom.clone()
                }
            }
            "Accessibility.enable" | "DOM.enable" => serde_json::json!({}),
            "DOM.getOuterHTML" => {
                serde_json::json!({"outerHTML":self.markup.as_deref().unwrap_or("")})
            }
            "Page.getFrameTree" => {
                let frame = |frame: &crate::snapshot_store::FrameDocument| serde_json::json!({"id":frame.frame_id,"parentId":frame.parent_id,"loaderId":frame.loader_id,"url":frame.url,"securityOrigin":frame.origin});
                serde_json::json!({"frameTree":{"frame":frame(&self.frames[0]),"childFrames":self.frames[1..].iter().map(|child| serde_json::json!({"frame":frame(child)})).collect::<Vec<_>>()}})
            }
            "DOM.getFrameOwner" => return Ok(()),
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

pub(super) fn thread_driver(nodes: Vec<Value>) -> CdpNavigationDriver<ThreadPipe> {
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
            scoped: scoped_fixture::ScopedDom::default(),
            fail_flattened: false,
            requests: Vec::new(),
            markup: None,
            frames: Vec::new(),
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

pub(super) fn driver_with_dom(nodes: Vec<Value>, dom: Value) -> CdpNavigationDriver<ThreadPipe> {
    let mut driver = thread_driver(nodes);
    driver.pipe.dom = dom;
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
fn scoped_classification_ignores_slow_whole_document_and_ad_ax_reads() {
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
            "scoped DOM facts must classify the reply: {:?}",
            reply.classification
        );
        assert!(clock.now().duration_since(start) <= Duration::from_secs(30));
        if stall_ads {
            assert!(observation.ax_truncated && observation.refs_truncated);
        }
        assert_eq!(driver.transport.pending_len(), 0);
    }
}

fn large_thread_driver() -> CdpNavigationDriver<ThreadPipe> {
    let comments = (0..18).map(|n| format!("comment{n}")).collect::<Vec<_>>();
    let mut nodes = vec![ax_node(
        "root",
        "region",
        "Comments",
        &comments.iter().map(String::as_str).collect::<Vec<_>>(),
        1,
        Some("frame-main"),
    )];
    let mut backend = 2;
    for comment in &comments {
        let replies = (0..160)
            .map(|n| format!("{comment}-reply{n}"))
            .collect::<Vec<_>>();
        nodes.push(ax_node(
            comment,
            "group",
            "Comment",
            &replies.iter().map(String::as_str).collect::<Vec<_>>(),
            backend,
            None,
        ));
        backend += 1;
        for reply in replies {
            nodes.push(ax_node(
                &reply,
                "button",
                "More replies",
                &[],
                backend,
                None,
            ));
            backend += 1;
        }
    }
    let mut driver = thread_driver(nodes);
    let mut dom = vec![
        serde_json::json!({"nodeId":99999,"backendNodeId":99999,"nodeType":9,"localName":"#document"}),
    ];
    for node in &driver.pipe.nodes {
        let backend = node["backendDOMNodeId"].as_u64().unwrap();
        let parent = driver
            .pipe
            .nodes
            .iter()
            .find(|p| p["childIds"].as_array().unwrap().contains(&node["nodeId"]))
            .map(|p| p["backendDOMNodeId"].as_u64().unwrap())
            .unwrap_or(99999);
        dom.push(serde_json::json!({"nodeId":backend,"backendNodeId":backend,"parentId":parent,"nodeType":1,"localName":"button","attributes":["type","button"]}));
    }
    driver.pipe.dom = serde_json::json!({"nodes":dom});
    driver.pipe.fail_flattened = true;
    driver.pipe.dom_polls = 30_000 / POLL_INTERVAL.as_millis() as usize;
    driver
}

#[test]
fn scoped_classification_does_not_starve_large_zoom_content() {
    let mut driver = large_thread_driver();
    let main = crate::snapshot_store::FrameDocument {
        navigation_revision: 0,
        frame_id: "frame-main".into(),
        parent_id: None,
        session_id: "session-own".into(),
        loader_id: "loader-main".into(),
        url: "https://example.com/".into(),
        origin: "https://example.com".into(),
    };
    let mut frames = vec![main.clone()];
    for n in 0..6 {
        frames.push(crate::snapshot_store::FrameDocument {
            frame_id: format!("ad-{n}"),
            parent_id: Some(main.frame_id.clone()),
            loader_id: format!("loader-ad-{n}"),
            ..main.clone()
        });
    }
    driver.pipe.frames = frames.clone();
    driver.frame_documents = frames.clone();
    driver
        .configured_frame_sessions
        .insert("session-own".into());
    driver.set_read_frames(frames);
    let mut clock = FakeClock::new();
    let started = clock.now();
    let reference = classification_index::test_refs(&parse_flattened_dom_nodes(serde_json::json!({"nodes":[{"nodeId":1,"backendNodeId":1,"nodeType":9,"localName":"#document"}]}).as_object().unwrap()).unwrap(), "target-own", "frame-main").remove(0);
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
    println!(
        "large zoom: records={}, elapsed={:?}, timings={:?}",
        observation.records.len(),
        clock.now().duration_since(started),
        driver.last_snapshot_timings()
    );
    assert_eq!(
        observation.records.len(),
        2899,
        "classification must not spend the content walk's deadline"
    );
    assert!(observation
        .refs
        .iter()
        .all(|reference| reference.classification.is_ok()));
    assert!(!driver
        .pipe
        .requests
        .iter()
        .any(|request| request["method"] == "DOM.getFlattenedDocument"));
    assert!(!driver
        .pipe
        .requests
        .iter()
        .any(|request| request["method"] == "DOM.getFrameOwner"));
    assert!(!observation.ax_truncated && !observation.refs_truncated);
    assert_eq!(driver.transport.pending_len(), 0);
    let rendered = state_text::render(&state_text::RenderInput {
        records: &observation.records,
        facts: &observation.facts,
        filters: &state_text::Filters::default(),
        page_url: "https://example.com/",
        snapshot_id: "0123456789abcdef0123456789abcdef",
        zoom: Some(state_text::Zoom {
            requested: "e1",
            target: Some("e1"),
        }),
        max_bytes: 262_144,
    });
    assert_eq!(rendered.text.matches("More replies").count(), 2880);
}

#[test]
fn unzoomed_filtered_refs_use_scoped_facts_when_flattening_fails() {
    let mut driver = thread_driver(vec![
        ax_node(
            "root",
            "RootWebArea",
            "Page",
            &["button"],
            1,
            Some("frame-main"),
        ),
        ax_node("button", "button", "More replies", &[], 2, None),
    ]);
    driver.pipe.fail_flattened = true;
    driver.pipe.dom_polls = 30_000 / POLL_INTERVAL.as_millis() as usize;
    let mut clock = FakeClock::new();
    let start = clock.now();
    let observation = driver
        .snapshot_with_clock(
            "route-own",
            SnapshotKind::Actionable,
            30_000,
            Some((7, "https://example.com/")),
            None,
            &[],
            &mut clock,
        )
        .unwrap();
    let rendered = state_text::render(&state_text::RenderInput {
        records: &observation.records,
        facts: &observation.facts,
        filters: &state_text::Filters {
            text: Some("More replies".into()),
            roles: vec![],
        },
        page_url: "https://example.com/",
        snapshot_id: "0123456789abcdef0123456789abcdef",
        zoom: None,
        max_bytes: 30_000,
    });
    println!(
        "filtered outline: elapsed={:?}, timings={:?}, text={}",
        clock.now().duration_since(start),
        driver.last_snapshot_timings(),
        rendered.text
    );
    assert!(rendered.printed_refs.contains("e2"));
    assert!(
        observation.refs[1].classification.is_ok(),
        "a printed filtered ref needs its own actual form facts: {:?}",
        observation.refs[1].classification
    );
}

#[test]
fn scoped_reads_match_whole_document_classification_records() {
    let dom = serde_json::json!({"nodes":[
        {"nodeId":1,"backendNodeId":1,"nodeType":9,"localName":"#document"},
        {"nodeId":2,"backendNodeId":2,"parentId":1,"nodeType":1,"localName":"body","attributes":[]},
        {"nodeId":3,"backendNodeId":3,"parentId":2,"nodeType":1,"localName":"form","attributes":["id","login","action","https://example.com/login"]},
        {"nodeId":4,"backendNodeId":4,"parentId":3,"nodeType":1,"localName":"input","attributes":["name","username","autocomplete","username"]},
        {"nodeId":5,"backendNodeId":5,"parentId":3,"nodeType":1,"localName":"input","attributes":["type","password","autocomplete","current-password"]},
        {"nodeId":6,"backendNodeId":6,"parentId":3,"nodeType":1,"localName":"button","attributes":["type","submit"]},
        {"nodeId":7,"backendNodeId":7,"parentId":2,"nodeType":1,"localName":"input","attributes":["form","login","autocomplete","username"]},
        {"nodeId":8,"backendNodeId":8,"parentId":2,"nodeType":1,"localName":"label","attributes":["for","card"]},
        {"nodeId":9,"backendNodeId":9,"parentId":2,"nodeType":1,"localName":"form","attributes":["id","payment"]},
        {"nodeId":10,"backendNodeId":10,"parentId":9,"nodeType":1,"localName":"input","attributes":["id","card","autocomplete","cc-number"]},
        {"nodeId":11,"backendNodeId":11,"parentId":9,"nodeType":1,"localName":"input","attributes":["autocomplete","cc-exp"]},
        {"nodeId":12,"backendNodeId":12,"parentId":9,"nodeType":1,"localName":"button","attributes":["type","submit"]},
        {"nodeId":13,"backendNodeId":13,"parentId":2,"nodeType":1,"localName":"input","attributes":["type","search","role","searchbox"]},
        {"nodeId":14,"backendNodeId":14,"parentId":3,"nodeType":1,"localName":"div","attributes":[],"shadowRoots":[{"nodeId":15,"backendNodeId":15}]},
        {"nodeId":15,"backendNodeId":15,"nodeType":11,"localName":"#document-fragment"},
        {"nodeId":16,"backendNodeId":16,"parentId":15,"nodeType":1,"localName":"input","attributes":["type","password"]},
        {"nodeId":17,"backendNodeId":17,"parentId":2,"nodeType":1,"localName":"iframe","attributes":[]},
        {"nodeId":18,"backendNodeId":18,"parentId":17,"nodeType":9,"localName":"#document"},
        {"nodeId":19,"backendNodeId":19,"parentId":18,"nodeType":1,"localName":"form","attributes":["id","login"]},
        {"nodeId":20,"backendNodeId":20,"parentId":19,"nodeType":1,"localName":"input","attributes":["autocomplete","cc-csc"]},
        {"nodeId":21,"backendNodeId":21,"parentId":19,"nodeType":1,"localName":"button","attributes":["type","submit"]}
    ]});
    let nodes = parse_flattened_dom_nodes(dom.as_object().unwrap()).unwrap();
    for backend in [4, 5, 6, 7, 8, 10, 11, 12, 13, 16, 20, 21] {
        let frame = if backend >= 20 {
            "frame-child"
        } else {
            "frame-main"
        };
        let identity = BackendNodeIdentity::new("target-own", frame, backend).unwrap();
        let expected =
            build_non_type_classification(&nodes, &identity, 7, "https://example.com").unwrap();
        let mut driver = driver_with_dom(
            vec![ax_node(
                "root",
                "textbox",
                "Field",
                &[],
                backend,
                Some(frame),
            )],
            dom.clone(),
        );
        let observation = driver
            .snapshot_with_clock(
                "route-own",
                SnapshotKind::Ax,
                30_000,
                Some((7, "https://example.com/")),
                None,
                &[],
                &mut FakeClock::new(),
            )
            .unwrap();
        let actual = observation.refs[0].classification.as_ref().unwrap();
        assert_eq!(
            actual.login_field, expected.login_field,
            "backend {backend}: exact login ordinals are not part of record serialization"
        );
        assert_eq!(
            serde_json::to_value(actual).unwrap(),
            serde_json::to_value(expected).unwrap(),
            "backend {backend}: complete records, including exact login ordinals"
        );
    }
}

#[test]
fn bounded_field_context_failure_does_not_poison_a_sibling_button() {
    let mut dom = vec![
        serde_json::json!({"nodeId":1,"backendNodeId":1,"nodeType":9,"localName":"#document"}),
        serde_json::json!({"nodeId":2,"backendNodeId":2,"parentId":1,"nodeType":1,"localName":"input","attributes":["type","password"]}),
        serde_json::json!({"nodeId":3,"backendNodeId":3,"parentId":1,"nodeType":1,"localName":"button","attributes":["type","button"]}),
    ];
    dom.extend((4..1000).map(|id| serde_json::json!({"nodeId":id,"backendNodeId":id,"parentId":1,"nodeType":1,"localName":"div","attributes":[]})));
    let mut driver = driver_with_dom(
        vec![
            ax_node(
                "root",
                "RootWebArea",
                "Page",
                &["field", "button"],
                1,
                Some("frame-main"),
            ),
            ax_node("field", "textbox", "Password", &[], 2, None),
            ax_node("button", "button", "More replies", &[], 3, None),
        ],
        serde_json::json!({"nodes":dom}),
    );
    let observation = driver
        .snapshot_with_clock(
            "route-own",
            SnapshotKind::Actionable,
            30_000,
            Some((7, "https://example.com/")),
            None,
            &[],
            &mut FakeClock::new(),
        )
        .unwrap();
    assert_eq!(
        observation.refs[1].classification,
        Err(ClassificationUnavailable::DomReadFailed)
    );
    assert!(observation.refs[2].classification.is_ok());
    assert_eq!(
        observation.facts["e2"].classification_unavailable,
        Some("dom_read_failed")
    );
    let rendered = state_text::render(&state_text::RenderInput {
        records: &observation.records,
        facts: &observation.facts,
        filters: &state_text::Filters {
            text: Some("More replies".into()),
            roles: vec![],
        },
        page_url: "https://example.com/",
        snapshot_id: "0123456789abcdef0123456789abcdef",
        zoom: None,
        max_bytes: 30_000,
    });
    assert!(rendered.printed_refs.contains("e3"));
}

#[test]
fn form_association_added_after_scope_discovery_refuses_instead_of_guessing() {
    let dom = serde_json::json!({"nodes":[
        {"nodeId":1,"backendNodeId":1,"nodeType":9,"localName":"#document"},
        {"nodeId":2,"backendNodeId":2,"parentId":1,"nodeType":1,"localName":"button","attributes":["type","submit"]},
        {"nodeId":3,"backendNodeId":3,"parentId":1,"nodeType":1,"localName":"form","attributes":["id","login"]},
        {"nodeId":4,"backendNodeId":4,"parentId":3,"nodeType":1,"localName":"input","attributes":["type","password"]}
    ]});
    let mut driver = driver_with_dom(
        vec![ax_node(
            "root",
            "button",
            "Sign in",
            &[],
            2,
            Some("frame-main"),
        )],
        dom,
    );
    driver.pipe.scoped.mutate_form_on_describe = Some(2);
    let observation = driver
        .snapshot_with_clock(
            "route-own",
            SnapshotKind::Ax,
            30_000,
            Some((7, "https://example.com/")),
            None,
            &[],
            &mut FakeClock::new(),
        )
        .unwrap();
    assert_eq!(observation.refs[0].classification, Err(ClassificationUnavailable::DomReadFailed), "a newly associated form is outside the observed context, not evidence that a submit is safe");
}
