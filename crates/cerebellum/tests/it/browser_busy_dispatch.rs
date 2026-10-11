use super::*;
use std::sync::Mutex;

const PRIVATE_NAME: &str = "private event payload not for durable storage";

struct FixturePipe {
    reads: VecDeque<Vec<u8>>,
    held: Option<Value>,
    block_once: Option<&'static str>,
    large_fanout: bool,
    hit_backend: u64,
    commands: Arc<Mutex<Vec<Value>>>,
    attachment: Option<AttachmentResponse>,
}

struct AttachmentResponse {
    downloads: std::path::PathBuf,
    denied: bool,
}

fn dom() -> Value {
    json!({"nodes":[
        {"nodeId":1,"backendNodeId":1,"nodeType":9,"nodeName":"#document","localName":"","nodeValue":""},
        {"nodeId":2,"backendNodeId":42,"parentId":1,"nodeType":1,"nodeName":"DIV","localName":"div","attributes":["onclick","openDrawer()"]},
        {"nodeId":3,"backendNodeId":43,"parentId":2,"nodeType":3,"nodeName":"#text","localName":"","nodeValue":"Event row"},
        {"nodeId":4,"backendNodeId":99,"parentId":1,"nodeType":1,"nodeName":"DIV","localName":"div","attributes":[]},
        {"nodeId":5,"backendNodeId":55,"parentId":2,"nodeType":1,"nodeName":"BUTTON","localName":"button","attributes":["type","submit"]}
    ]})
}

fn ax(id: u64, backend: u64, role: &str, name: &str, children: &[u64]) -> Value {
    json!({"nodeId":id.to_string(),"backendDOMNodeId":backend,"frameId":"frame-main","ignored":false,"role":{"value":role},"name":{"value":name},"childIds":children.iter().map(u64::to_string).collect::<Vec<_>>()})
}

impl FixturePipe {
    fn queue(&mut self, frame: Value) {
        let mut bytes = serde_json::to_vec(&frame).unwrap();
        bytes.push(0);
        self.reads.push_back(bytes);
    }
}

impl CdpPipeIo for FixturePipe {
    fn write_frame(&mut self, bytes: &[u8]) -> io::Result<()> {
        let command: Value = serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap();
        self.commands.lock().unwrap().push(command.clone());
        let method = command["method"].as_str().unwrap();
        let result = match method {
            "Browser.setDownloadBehavior" => {
                assert!(
                    command.get("sessionId").is_none(),
                    "download policy belongs to the browser session"
                );
                if let Some(attachment) = self.attachment.as_mut() {
                    attachment.denied = command["params"]["behavior"] == "deny";
                }
                json!({})
            }
            "Target.createTarget" => json!({"targetId":"target-own"}),
            "Target.attachToTarget" => json!({"sessionId":"session-own"}),
            "Page.navigate" if self.attachment.is_some() => {
                let attachment = self.attachment.as_ref().unwrap();
                if !attachment.denied {
                    std::fs::write(attachment.downloads.join("report.txt"), "fixture payload")
                        .unwrap();
                }
                self.queue(json!({"method":"Browser.downloadWillBegin","params":{"frameId":"target-own","guid":"navigation-download","url":"https://requested.example/attachment","suggestedFilename":"report.txt"}}));
                json!({"frameId":"target-own","isDownload":true,"errorText":"net::ERR_ABORTED"})
            }
            "Accessibility.getRootAXNode" => json!({"node":ax(1,1,"RootWebArea","Events",&[2])}),
            "Accessibility.getChildAXNodes" if command["params"]["id"] == "1" => {
                let children = if self.large_fanout {
                    (100..20_100).collect::<Vec<_>>()
                } else {
                    vec![3]
                };
                json!({"nodes":[ax(2,42,"generic","",&children)]})
            }
            "Accessibility.getChildAXNodes" => {
                json!({"nodes":[ax(3,43,"StaticText","Event row",&[])]})
            }
            "DOM.getFlattenedDocument" => {
                let mut document = dom();
                if self.attachment.is_some() {
                    document["nodes"][1]["localName"] = json!("a");
                    document["nodes"][1]["nodeName"] = json!("A");
                    document["nodes"][1]["attributes"] =
                        json!(["href", "https://requested.example/attachment"]);
                }
                document
            }
            "DOM.getDocument" => json!({"root":{"nodeId":1}}),
            "DOM.getOuterHTML" => json!({"outerHTML":"<div>Event row</div>"}),
            "Page.getFrameTree" => {
                json!({"frameTree":{"frame":{"id":"frame-main","loaderId":"loader-page","url":"https://requested.example/page","securityOrigin":"https://requested.example"}}})
            }
            "Page.getNavigationHistory" => {
                json!({"currentIndex":0,"entries":[{"id":1,"url":"https://requested.example/page"}]})
            }
            "DOM.getContentQuads" => json!({"quads":[[0,0,100,0,100,40,0,40]]}),
            "Page.getLayoutMetrics" => {
                json!({"cssVisualViewport":{"pageX":0,"pageY":0,"offsetX":0,"offsetY":0,"clientWidth":800,"clientHeight":600,"scale":1}})
            }
            "DOM.getNodeForLocation" => {
                json!({"backendNodeId":self.hit_backend,"frameId":"frame-main"})
            }
            "DOM.describeNode" => {
                json!({"node":{"backendNodeId":command["params"]["backendNodeId"],"children":if command["params"]["backendNodeId"] == 42 {json!([{"backendNodeId":55}])} else {json!([])}}})
            }
            "Accessibility.getPartialAXTree" => {
                json!({"nodes":[ax(99,99,"generic",PRIVATE_NAME,&[])]})
            }
            "Page.enable"
            | "Network.enable"
            | "DOM.enable"
            | "Accessibility.enable"
            | "DOM.scrollIntoViewIfNeeded"
            | "Input.dispatchMouseEvent" => json!({}),
            other => panic!("unexpected fixture command {other}"),
        };
        let mut response = json!({"id":command["id"],"result":result});
        if let Some(session) = command.get("sessionId") {
            response["sessionId"] = session.clone();
        }
        if let Some(held) = self.held.take() {
            self.queue(held);
        }
        if method == "Input.dispatchMouseEvent" && command["params"]["type"] == "mouseReleased" {
            if let Some(attachment) = self.attachment.as_ref() {
                // The browser double models an attachment response at the disk
                // boundary: without Chrome's deny policy it saves the payload.
                if !attachment.denied {
                    std::fs::write(attachment.downloads.join("report.txt"), "fixture payload")
                        .unwrap();
                }
                self.queue(json!({"method":"Network.responseReceived","sessionId":"session-own","params":{"requestId":"attachment","frameId":"target-own","type":"Document","response":{"status":200,"statusText":"OK","headers":{"Content-Disposition":"attachment; filename=report.txt"}}}}));
                self.queue(json!({"method":"Browser.downloadWillBegin","params":{"frameId":"target-own","guid":"fixture-download","url":"https://requested.example/attachment","suggestedFilename":"report.txt"}}));
            }
        }
        if self.block_once == Some(method) {
            self.block_once = None;
            self.held = Some(response);
        } else {
            self.queue(response);
        }
        Ok(())
    }

    fn read(&mut self, destination: &mut [u8]) -> io::Result<PipeRead> {
        let Some(bytes) = self.reads.pop_front() else {
            return Ok(PipeRead::WouldBlock);
        };
        let count = bytes.len().min(destination.len());
        destination[..count].copy_from_slice(&bytes[..count]);
        if count < bytes.len() {
            self.reads.push_front(bytes[count..].to_vec());
        }
        Ok(PipeRead::Bytes(count))
    }
}

struct FixtureProcess {
    driver: CdpNavigationDriver<FixturePipe>,
    read_document: bool,
    refusal: Option<ClickDriveError>,
}

impl OwnedBrowserProcess for FixtureProcess {
    fn navigate(
        &mut self,
        context: &str,
        url: &str,
        wait: NavigationWait,
        deadline: u64,
        tracker: &mut Tracker,
    ) -> Result<(), NavigationDriveError> {
        self.driver.navigate(context, url, wait, deadline, tracker)
    }
    fn committed_document(
        &mut self,
        context: &str,
        deadline: u64,
    ) -> Result<CommittedDocument, NavigationDriveError> {
        if self.read_document {
            self.driver.committed_document(context, deadline)
        } else {
            Ok(page_document())
        }
    }
    fn snapshot_classified(
        &mut self,
        context: &str,
        kind: SnapshotKind,
        epoch: u64,
        origin: &str,
        deadline: u64,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        self.driver
            .snapshot_classified(context, kind, epoch, origin, deadline)
    }
    fn click_classified(
        &mut self,
        context: &str,
        identity: &BackendNodeIdentity,
        epoch: u64,
        origin: &str,
        expected: Option<&cerebellum::classification::NonTypeClassificationRecord>,
        deadline: u64,
        input: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        if let Some(refusal) = &self.refusal {
            return Err(refusal.clone());
        }
        self.driver
            .click_classified(context, identity, epoch, origin, expected, deadline, input)
    }
    fn generation_matches(&self) -> bool {
        true
    }
    fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
        Ok(())
    }
    fn wait_for_exit(&mut self, _: Duration) -> Result<bool, ProcessControlFailure> {
        Ok(true)
    }
    fn force_terminate(&mut self) -> Result<(), ProcessControlFailure> {
        Ok(())
    }
    fn wait_until_reaped(&mut self) -> Result<(), ProcessControlFailure> {
        Ok(())
    }
}

async fn fixture(
    block_once: Option<&'static str>,
    hit_backend: u64,
    refusal: Option<ClickDriveError>,
) -> (BrowserPlane, RouteIdentity, Arc<Mutex<Vec<Value>>>) {
    let route = identity();
    let commands = Arc::new(Mutex::new(Vec::new()));
    let pipe = FixturePipe {
        reads: VecDeque::new(),
        held: None,
        block_once: block_once.filter(|method| *method != "large_fanout"),
        large_fanout: block_once == Some("large_fanout"),
        hit_backend,
        commands: commands.clone(),
        attachment: None,
    };
    let process = FixtureProcess {
        driver: CdpNavigationDriver::new(pipe, CdpTransport::new(), CdpFrameDecoder::default()),
        read_document: block_once == Some("Page.getFrameTree"),
        refusal,
    };
    let plane = plane_with_process(&route, Box::new(process), 150)
        .with_result_schema_enforcement(
            cerebellum::computer_capability::ResultSchemaEnforcement::Withhold,
        )
        .with_in_memory_journal(cerebellum::journal::JournalConfig {
            journal_retention_bytes: 1_048_576,
            journal_max_entry_bytes: 65_536,
        });
    plane.open_context(route.clone()).await.unwrap();
    (plane, route, commands)
}

async fn click_text(plane: &BrowserPlane, route: &RouteIdentity, snapshot: &Value) -> Value {
    let text = snapshot["state_text"].as_str().unwrap();
    let reference = text
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|node| node["role"] == "StaticText")
        .unwrap()["ref"]
        .as_str()
        .unwrap()
        .to_string();
    plane.dispatch(route,BrowserCapability::Click,&json!({"ref":reference,"snapshot_id":snapshot["snapshot_id"],"intent":"open local event drawer","severity":{"tier":2,"credential":false,"financial":false}})).await
}

#[tokio::test]
async fn busy_snapshot_timeout_names_step_and_recovers_through_dispatch() {
    for step in [
        "Accessibility.getRootAXNode",
        "DOM.getOuterHTML",
        "Page.getFrameTree",
    ] {
        let (plane, route, _) = fixture(Some(step), 42, None).await;
        let request = json!({"mode":if step == "DOM.getOuterHTML" {"dom_full"} else {"ax"}});
        let refused = plane
            .dispatch(&route, BrowserCapability::Snapshot, &request)
            .await;
        assert_eq!(refused["outcome"], "command_timeout", "{step}: {refused}");
        assert_eq!(refused["detail"]["step"], step);
        assert_eq!(refused["detail"]["command_sent"], true);
        assert!(refused["remedy"].as_str().unwrap().contains("settle"));
        let fresh = plane
            .dispatch(&route, BrowserCapability::Snapshot, &request)
            .await;
        assert_eq!(fresh["outcome"], "ok", "recovery after {step}: {fresh}");
        assert!(fresh["state_text"].as_str().unwrap().contains("Event row"));
    }
}

#[tokio::test]
async fn busy_snapshot_child_deadline_returns_bounded_partial_through_dispatch() {
    let (plane, route, _) = fixture(Some("Accessibility.getChildAXNodes"), 42, None).await;
    let partial = plane
        .dispatch(&route, BrowserCapability::Snapshot, &json!({"mode":"ax"}))
        .await;
    assert_eq!(partial["outcome"], "ok", "{partial}");
    assert_eq!(partial["truncated"], true);
    assert_eq!(partial["refs_truncated"], true);
    assert!(partial["state_text"].as_str().unwrap().contains("Events"));
    let fresh = plane
        .dispatch(&route, BrowserCapability::Snapshot, &json!({"mode":"ax"}))
        .await;
    assert_eq!(fresh["outcome"], "ok", "{fresh}");
    assert_eq!(fresh["truncated"], false);
    assert!(fresh["state_text"].as_str().unwrap().contains("Event row"));
}

#[tokio::test]
async fn busy_text_ref_click_activates_element_ancestor_through_dispatch() {
    let (plane, route, commands) = fixture(None, 42, None).await;
    let snapshot = plane
        .dispatch(&route, BrowserCapability::Snapshot, &json!({"mode":"ax"}))
        .await;
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    let clicked = click_text(&plane, &route, &snapshot).await;
    assert_eq!(clicked["outcome"], "ok", "{clicked}");
    assert_eq!(
        clicked["activated_element"]["identity"],
        cerebellum::classification::NodeIdentityInput::new("target-own", "frame-main", 42)
            .identity()
            .unwrap()
    );
    let commands = commands.lock().unwrap();
    assert!(commands
        .iter()
        .any(|c| c["method"] == "DOM.getContentQuads" && c["params"]["backendNodeId"] == 42));
    assert_eq!(
        commands
            .iter()
            .filter(|c| c["method"] == "Input.dispatchMouseEvent")
            .count(),
        2
    );
}

#[tokio::test]
async fn busy_text_overlay_refuses_and_journals_exact_outcome_without_page_text() {
    let (plane, route, commands) = fixture(None, 99, None).await;
    let snapshot = plane
        .dispatch(&route, BrowserCapability::Snapshot, &json!({"mode":"ax"}))
        .await;
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    let refused = click_text(&plane, &route, &snapshot).await;
    assert_eq!(refused["outcome"], "element_intercepted", "{refused}");
    assert_eq!(refused["detail"]["hit_inside_target"], false);
    assert_eq!(refused["detail"]["hit_name"], PRIVATE_NAME);
    assert_eq!(
        commands
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c["method"] == "Input.dispatchMouseEvent")
            .count(),
        0
    );
    let export = plane.journal_export_for_test().await;
    let click = export
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .rfind(|e| e["capability"] == "browser.click")
        .unwrap();
    assert_eq!(click["outcome"], "invalid_request");
    let detail = &click["detail"];
    assert_eq!(detail["outcome"], "element_intercepted");
    assert!(
        !detail.to_string().contains(PRIVATE_NAME),
        "page text leaked: {detail}"
    );
    assert!(detail.get("hit_name").is_none());
}

#[tokio::test]
async fn busy_click_typed_refusals_keep_their_journal_classification() {
    let viewport = ViewportRefusal {
        position: BrowserClickPosition {
            x_css: 900.0,
            y_css: 900.0,
        },
        viewport: InputRect::new(0.0, 0.0, 800.0, 600.0),
    };
    for (refusal, wire, journal) in [
        (
            ClickDriveError::NoPosition,
            "element_intercepted",
            "invalid_request",
        ),
        (
            ClickDriveError::ClassificationChanged,
            "stale_snapshot",
            "stale_snapshot",
        ),
        (
            ClickDriveError::OutsideViewportAfterScroll(viewport),
            "outside_viewport_after_scroll",
            "invalid_request",
        ),
    ] {
        let (plane, route, _) = fixture(None, 42, Some(refusal)).await;
        let snapshot = plane
            .dispatch(&route, BrowserCapability::Snapshot, &json!({"mode":"ax"}))
            .await;
        assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
        let refused = click_text(&plane, &route, &snapshot).await;
        assert_eq!(refused["outcome"], wire, "{refused}");
        let export = plane.journal_export_for_test().await;
        let click = export
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .rfind(|e| e["capability"] == "browser.click")
            .unwrap();
        assert_eq!(click["outcome"], journal, "{click}");
        assert_eq!(click["detail"]["outcome"], wire, "{click}");
    }
}

#[tokio::test]
async fn busy_text_ancestor_cannot_lend_permission_to_a_nested_submit() {
    let (plane, route, commands) = fixture(None, 55, None).await;
    let snapshot = plane
        .dispatch(&route, BrowserCapability::Snapshot, &json!({"mode":"ax"}))
        .await;
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    let refused = click_text(&plane, &route, &snapshot).await;
    assert_eq!(refused["outcome"], "element_intercepted", "{refused}");
    assert_eq!(
        refused["detail"]["reason_code"],
        "text_ancestor_activation_mismatch"
    );
    assert_eq!(
        commands
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c["method"] == "Input.dispatchMouseEvent")
            .count(),
        0
    );
}

#[tokio::test]
async fn busy_snapshot_large_fanout_is_partial_without_requesting_the_huge_subtree() {
    let (plane, route, commands) = fixture(Some("large_fanout"), 42, None).await;
    let partial = plane
        .dispatch(&route, BrowserCapability::Snapshot, &json!({"mode":"ax"}))
        .await;
    assert_eq!(partial["outcome"], "ok", "{partial}");
    assert_eq!(partial["truncated"], true);
    assert_eq!(partial["refs_truncated"], true);
    assert!(!commands
        .lock()
        .unwrap()
        .iter()
        .any(|c| c["method"] == "DOM.getFlattenedDocument"));
    assert_eq!(
        commands
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c["method"] == "Accessibility.getChildAXNodes")
            .count(),
        1
    );
}

#[tokio::test]
async fn an_attachment_click_is_blocked_without_writing_downloads_even_after_relaunch() {
    let scratch = cortexkit_test_support::ScratchDir::new("browser-attachment-deny");
    for launch in 0..2 {
        let downloads = scratch.join(format!("profile-{launch}/Downloads"));
        cerebellum_core::private_fs::create_dir_all(&downloads).unwrap();
        let route = identity();
        let commands = Arc::new(Mutex::new(Vec::new()));
        let pipe = FixturePipe {
            reads: VecDeque::new(),
            held: None,
            block_once: None,
            large_fanout: false,
            hit_backend: 42,
            commands: Arc::clone(&commands),
            attachment: Some(AttachmentResponse {
                downloads: downloads.clone(),
                denied: false,
            }),
        };
        let process = FixtureProcess {
            driver: CdpNavigationDriver::new(pipe, CdpTransport::new(), CdpFrameDecoder::default()),
            read_document: false,
            refusal: None,
        };
        let plane = plane_with_process(&route, Box::new(process), 150)
            .with_grants_installed(GrantStore::default().with_public_web_baseline(Arc::new(
                cerebellum::browser_signed_in::SignedInDomains::default(),
            )))
            .with_result_schema_enforcement(
                cerebellum::computer_capability::ResultSchemaEnforcement::Withhold,
            );
        plane.open_context(route.clone()).await.unwrap();
        let snapshot = plane
            .serve(&route, BrowserCapability::Snapshot, &json!({"mode":"ax"}))
            .await
            .unwrap();
        assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
        let reply = click_text(&plane, &route, &snapshot).await;
        assert_eq!(
            std::fs::read_dir(&downloads).unwrap().count(),
            0,
            "an attachment wrote into {}",
            downloads.display()
        );
        assert_eq!(reply["outcome"], "unsupported_download", "{reply}");
        assert!(reply["remedy"]
            .as_str()
            .unwrap()
            .contains("download was blocked"));
        assert!(reply["lifecycle"]["events"]
            .as_array()
            .unwrap()
            .contains(&json!("download_blocked")));
        cerebellum::browser::validate_browser_result("browser.click", &reply).unwrap();
        let navigated = plane.serve(&route, BrowserCapability::Navigate, &json!({"url":"https://requested.example/attachment","intent":"read an attachment URL","wait":"settle","severity":{"tier":1,"credential":false,"financial":false}})).await.unwrap();
        assert_eq!(navigated["outcome"], "unsupported_download", "{navigated}");
        assert!(navigated["remedy"]
            .as_str()
            .unwrap()
            .contains("download was blocked"));
        assert_eq!(std::fs::read_dir(&downloads).unwrap().count(), 0);
        let commands = commands.lock().unwrap();
        let deny = commands
            .iter()
            .position(|command| command["method"] == "Browser.setDownloadBehavior")
            .unwrap();
        let target = commands
            .iter()
            .position(|command| command["method"] == "Target.createTarget")
            .unwrap();
        assert!(
            deny < target,
            "download denial must precede opening any owned target"
        );
        assert_eq!(
            commands[deny]["params"],
            json!({"behavior":"deny","eventsEnabled":true})
        );
    }
}
