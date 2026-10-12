use super::*;

#[test]
fn user_actions_require_explicit_tabs_and_closed_arguments() {
    for action in [
        "snapshot",
        "screenshot",
        "navigate",
        "click",
        "type",
        "click_point",
    ] {
        assert!(validate(action, &json!({})).is_err(), "{action}");
    }
    assert!(validate("open_tab", &json!({})).is_ok());
    assert!(validate("claim_tab", &json!({"tab":"t"})).is_ok());
    assert!(validate("close", &json!({})).is_ok());
    assert!(validate("snapshot", &json!({"tab":"t","unexpected":true})).is_err());
}

#[test]
fn snapshot_and_ref_reuse_is_scoped_to_route_tab_and_connection() {
    let target = UserBrowser::new(Arc::new(StandingBrowserGrants::in_memory()));
    let route = Route {
        channel: 1,
        epoch: 1,
    };
    let other = Route {
        channel: 2,
        epoch: 1,
    };
    let snapshot = Snapshot {
        route,
        tab: "tab1".into(),
        connection: 7,
        interaction: 2,
        document: CommittedDocument::new("https://example.com/", 1, "loader"),
        refs: BTreeMap::new(),
        image: None,
    };
    target.synchronize(7);
    target.retain("us1".into(), snapshot);
    assert!(target
        .snapshot(route, "tab1", 7, &json!({"snapshot_id":"us1"}))
        .is_ok());
    assert!(target
        .snapshot(other, "tab1", 7, &json!({"snapshot_id":"us1"}))
        .is_err());
    assert!(target
        .snapshot(route, "tab2", 7, &json!({"snapshot_id":"us1"}))
        .is_err());
    assert!(target
        .snapshot(route, "tab1", 8, &json!({"snapshot_id":"us1"}))
        .is_err());
    assert!(target
        .snapshot(route, "tab1", 7, &json!({"snapshot_id":"own-snapshot"}))
        .is_err());
}

use crate::user_browser_bridge::{Message, MessageBody};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone)]
struct DoubleTab {
    owner: Option<Route>,
    handed: bool,
    group: bool,
    url: String,
    loader: u64,
    interaction: u64,
}

#[derive(Default)]
struct DoubleState {
    tabs: BTreeMap<String, DoubleTab>,
    commands: Vec<Value>,
    inputs: Vec<String>,
    captures: Vec<String>,
    redirect: Option<String>,
    human_before_input: bool,
    human_after_input: bool,
    popup: bool,
    popup_once_on_metadata: bool,
    new_tab_link: bool,
    password: bool,
    payment: bool,
    remove_group_on_card: bool,
    foreign_hit: bool,
    viewport_changed: bool,
}

struct Fixture {
    planes: Arc<Planes>,
    state: Arc<Mutex<DoubleState>>,
    epoch: u64,
    corr: AtomicU64,
    worker: tokio::task::JoinHandle<()>,
}

impl Fixture {
    fn new() -> Self {
        let mut planes =
            crate::isolated_test_planes(&Arc::new(cerebellum_core::health::HealthState::new()));
        let grants = Arc::new(StandingBrowserGrants::open(
            Arc::new(crate::browser_standing_grants::InMemoryStandingGrantStorage::new()),
            Some("test-machine".into()),
        ));
        planes.user_browser = UserBrowserBridge::with_user_grants(grants);
        let planes = Arc::new(planes);
        for channel in [1, 2] {
            let frame = tool_frame(channel, 1, json!({"action":"status"}));
            crate::install_test_bind(&planes.routes, &frame);
            let mut facts = planes.routes.get(channel, 1).unwrap();
            facts.consumer_capabilities = vec!["elicitation".into()];
            planes.routes.insert(channel, 1, facts);
        }
        let (epoch, mut commands) = planes.user_browser.connect_for_policy_test();
        let state = Arc::new(Mutex::new(DoubleState::default()));
        state.lock().unwrap().tabs.insert(
            "handed".into(),
            DoubleTab {
                owner: None,
                handed: true,
                group: true,
                url: "https://example.com/".into(),
                loader: 1,
                interaction: 1,
            },
        );
        state.lock().unwrap().tabs.insert(
            "outside".into(),
            DoubleTab {
                owner: None,
                handed: false,
                group: false,
                url: "https://private.example/secret".into(),
                loader: 1,
                interaction: 1,
            },
        );
        let bridge = planes.user_browser.clone();
        let worker_state = state.clone();
        let worker = tokio::spawn(async move {
            let mut pending = BTreeMap::new();
            while let Some(message) = commands.recv().await {
                match message.body {
                    MessageBody::Attach { route, command } => {
                        pending.insert(message.id, (route, command));
                        bridge.receive_for_policy_test(Message {
                            id: message.id,
                            epoch,
                            body: MessageBody::Attached,
                        });
                    }
                    MessageBody::Dispatch => {
                        let (route, command) = pending.remove(&message.id).unwrap();
                        let mut state = worker_state.lock().unwrap();
                        let result = execute(&mut state, route, epoch, &command);
                        let input = result.as_ref().is_ok_and(|(_, input)| *input);
                        bridge.receive_for_policy_test(Message {
                            id: message.id,
                            epoch,
                            body: MessageBody::Dispatched {
                                input_dispatched: input,
                            },
                        });
                        let body = match result {
                            Ok((result, _)) => MessageBody::Completed {
                                result,
                                input_dispatched: input,
                                detached: true,
                            },
                            Err(reason) => MessageBody::Refused {
                                reason: json!({"reason":reason,"remedy":if reason == "state_changed_by_person" { "read again" } else { "use an eligible claimed Agent-group tab" }}).to_string(),
                                input_dispatched: false,
                                detached: true,
                            },
                        };
                        bridge.receive_for_policy_test(Message {
                            id: message.id,
                            epoch,
                            body,
                        });
                        if input && state.human_after_input {
                            state.human_after_input = false;
                            state
                                .tabs
                                .get_mut(command["tab"].as_str().unwrap())
                                .unwrap()
                                .interaction += 1;
                        }
                    }
                    MessageBody::Goodbye { route } => {
                        release_double(&mut worker_state.lock().unwrap(), route)
                    }
                    MessageBody::Cancel => {
                        pending.remove(&message.id);
                        bridge.receive_for_policy_test(Message {
                            id: message.id,
                            epoch,
                            body: MessageBody::Cancelled {
                                input_dispatched: false,
                                detached: true,
                            },
                        });
                    }
                    _ => panic!("unexpected server message"),
                }
            }
        });
        Self {
            planes,
            state,
            epoch,
            corr: AtomicU64::new(10),
            worker,
        }
    }

    async fn call(&self, channel: u16, args: Value, decision: &str) -> (Value, Vec<Value>) {
        let corr = self.corr.fetch_add(1, Ordering::Relaxed);
        let frame = tool_frame(channel, corr, args);
        let _registration = self.planes.cancellations.register((channel, 1, corr));
        let (writer, mut replies) = mpsc::channel(16);
        let planes = self.planes.clone();
        let arrival = crate::browser_queue::arrive(&frame, &planes);
        let task = tokio::spawn(async move {
            crate::browser_queue::scope(
                arrival,
                crate::handle_tool_request(frame, &writer, &planes, &crate::CallObservation::new()),
            )
            .await
            .unwrap();
        });
        let mut cards = Vec::new();
        let response = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let frame = replies.recv().await.expect("tool response");
                let body: Value = serde_json::from_slice(&frame.body).unwrap();
                if frame.header.ty == subc_protocol::FrameType::Request {
                    cards.push(body);
                    {
                        let mut state = self.state.lock().unwrap();
                        if state.remove_group_on_card {
                            state.remove_group_on_card = false;
                            state.tabs.get_mut("handed").unwrap().group = false;
                        }
                    }
                    assert!(self.planes.elicitor.deliver(
                        channel,
                        frame.header.corr,
                        json!({"decision":decision})
                    ));
                } else if matches!(
                    frame.header.ty,
                    subc_protocol::FrameType::Response | subc_protocol::FrameType::Error
                ) {
                    break body;
                }
            }
        })
        .await
        .expect("bounded tool invocation");
        task.await.unwrap();
        (response, cards)
    }

    async fn claim(&self, channel: u16) -> String {
        let (reply, _) = self
            .call(
                channel,
                json!({"browser":"user","action":"claim_tab","tab":"handed"}),
                "allow_once",
            )
            .await;
        assert_eq!(reply["outcome"], "ok", "{reply}");
        reply["tab"].as_str().unwrap().into()
    }

    async fn snapshot(&self, channel: u16, tab: &str, decision: &str) -> (Value, Vec<Value>) {
        self.call(
            channel,
            json!({"browser":"user","action":"snapshot","tab":tab}),
            decision,
        )
        .await
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.planes.user_browser.shutdown();
        self.worker.abort();
    }
}

fn tool_frame(channel: u16, corr: u64, args: Value) -> Frame {
    Frame::build(
        subc_protocol::FrameType::Request,
        subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
        channel,
        1,
        corr,
        serde_json::to_vec(&json!({"name":"browser_use","arguments":args})).unwrap(),
    )
    .unwrap()
}

fn release_double(state: &mut DoubleState, route: Route) {
    for tab in state
        .tabs
        .values_mut()
        .filter(|tab| tab.owner == Some(route))
    {
        tab.owner = None;
        if tab.handed {
            tab.group = false;
            tab.handed = false;
        }
    }
}

fn execute(
    state: &mut DoubleState,
    route: Route,
    epoch: u64,
    command: &Value,
) -> Result<(Value, bool), String> {
    assert_eq!(command["version"], 1);
    state.commands.push(command.clone());
    let name = command["action"].as_str().unwrap();
    if name == "status" {
        let tabs: Vec<_> = state.tabs.iter().filter(|(_, tab)| tab.group && (tab.owner == Some(route) || (tab.owner.is_none() && tab.handed))).map(|(handle, tab)| json!({"tab":handle,"claimed":tab.owner == Some(route),"handed":tab.handed,"interaction_epoch":tab.interaction})).collect();
        return Ok((json!({"tabs":tabs,"connection_epoch":epoch}), false));
    }
    if name == "close" {
        release_double(state, route);
        return Ok((json!({"connection_epoch":epoch}), false));
    }
    if name == "open_tab" {
        let handle = format!("opened{}", state.tabs.len());
        state.tabs.insert(
            handle.clone(),
            DoubleTab {
                owner: Some(route),
                handed: false,
                group: true,
                url: command["url"].as_str().unwrap_or("about:blank").into(),
                loader: 1,
                interaction: 1,
            },
        );
        return Ok((
            json!({"tab":handle,"interaction_epoch":1,"connection_epoch":epoch}),
            false,
        ));
    }
    let handle = command["tab"].as_str().unwrap();
    let tab = state.tabs.get_mut(handle).ok_or("tab_not_visible")?;
    if !tab.group {
        return Err("outside_agent_group".into());
    }
    if name == "claim_tab" {
        if tab.owner.is_some_and(|owner| owner != route) {
            return Err("tab_already_claimed".into());
        }
        if !tab.handed {
            return Err("tab_not_visible".into());
        }
        tab.owner = Some(route);
        return Ok((
            json!({"tab":handle,"interaction_epoch":tab.interaction,"connection_epoch":epoch}),
            false,
        ));
    }
    if tab.owner != Some(route) {
        return Err("tab_not_claimed_by_route".into());
    }
    assert_eq!(name, "cdp");
    let commands = command["commands"].as_array().unwrap();
    let input = commands.iter().any(|command| {
        command["method"].as_str().unwrap().starts_with("Input.")
            || command["method"] == "DOM.focus"
    });
    if input && state.human_before_input {
        tab.interaction += 1;
        state.human_before_input = false;
    }
    if command
        .get("interaction_epoch")
        .is_some_and(|expected| expected != tab.interaction)
    {
        return Err("state_changed_by_person".into());
    }
    let metadata_popup = state.popup_once_on_metadata
        && commands
            .iter()
            .any(|command| command["method"] == "Page.getNavigationHistory");
    if metadata_popup {
        state.popup_once_on_metadata = false;
    }
    let mut results = Vec::new();
    for command in commands {
        let method = command["method"].as_str().unwrap();
        let result = match method {
            "Page.getNavigationHistory" => {
                json!({"currentIndex":0,"entries":[{"id":tab.loader,"url":tab.url}]})
            }
            "Page.getFrameTree" => {
                json!({"frameTree":{"frame":{"id":"main","loaderId":format!("l{}",tab.loader),"url":tab.url},"childFrames":[{"frame":{"id":"foreign","parentId":"main","loaderId":"foreign-loader","url":"https://ungranted.example/secret"}}]}})
            }
            "Page.navigate" => {
                tab.url = state
                    .redirect
                    .clone()
                    .unwrap_or_else(|| command["params"]["url"].as_str().unwrap().into());
                tab.loader += 1;
                json!({"frameId":"main","loaderId":format!("l{}",tab.loader)})
            }
            "Accessibility.getFullAXTree" => {
                state
                    .captures
                    .push(command["params"]["frameId"].as_str().unwrap().into());
                ax()
            }
            "DOM.getFlattenedDocument" => dom(state.new_tab_link, state.password, state.payment),
            "DOM.getContentQuads" => json!({"quads":[[0,0,20,0,20,20,0,20]]}),
            "DOM.getNodeForLocation" => {
                json!({"backendNodeId":3,"frameId":if state.foreign_hit { "foreign" } else { "main" }})
            }
            "Page.getLayoutMetrics" => {
                json!({"cssVisualViewport":{"offsetX":0,"offsetY":0,"pageX":0,"pageY":0,"clientWidth":if state.viewport_changed {200} else {100},"clientHeight":100,"scale":1}})
            }
            "Page.captureScreenshot" => {
                json!({"data":"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg=="})
            }
            "DOM.resolveNode" => json!({"object":{"objectId":"typed-node"}}),
            "Runtime.callFunctionOn" => json!({"result":{"value":true}}),
            "Input.dispatchMouseEvent"
            | "Input.insertText"
            | "Input.dispatchKeyEvent"
            | "DOM.focus" => {
                state.inputs.push(method.into());
                json!({})
            }
            "Accessibility.enable"
            | "DOM.enable"
            | "Runtime.enable"
            | "Emulation.setFocusEmulationEnabled" => json!({}),
            _ => panic!("unexpected CDP method: {method}"),
        };
        results.push(json!({"result":result}));
    }
    Ok((
        json!({"tab":handle,"results":results,"interaction_epoch":tab.interaction,"connection_epoch":epoch,"popup_activated_briefly":state.popup || metadata_popup}),
        input,
    ))
}

fn ax() -> Value {
    json!({"nodes":[
        {"nodeId":"root","ignored":false,"role":{"value":"RootWebArea"},"name":{"value":"Page"},"backendDOMNodeId":1,"frameId":"main","childIds":["button","text","secret","foreign"]},
        {"nodeId":"button","ignored":false,"role":{"value":"button"},"name":{"value":"Go"},"backendDOMNodeId":3},
        {"nodeId":"text","ignored":false,"role":{"value":"textbox"},"name":{"value":"Message"},"backendDOMNodeId":4},
        {"nodeId":"secret","ignored":false,"role":{"value":"textbox"},"name":{"value":"Password"},"value":{"value":"secret-value"},"backendDOMNodeId":5},
        {"nodeId":"foreign","ignored":false,"role":{"value":"RootWebArea"},"name":{"value":"FOREIGN_SECRET"},"frameId":"foreign","childIds":["foreign-child"]},
        {"nodeId":"foreign-child","ignored":false,"role":{"value":"StaticText"},"name":{"value":"FOREIGN_CHILD_SECRET"}}
    ]})
}

fn dom(new_tab: bool, password: bool, payment: bool) -> Value {
    json!({"nodes":[
        {"nodeId":1,"backendNodeId":1,"nodeType":9,"nodeName":"#document","localName":"","nodeValue":""},
        {"nodeId":2,"parentId":1,"backendNodeId":2,"nodeType":1,"nodeName":"DIV","localName":"div","attributes":[]},
        {"nodeId":3,"parentId":2,"backendNodeId":3,"nodeType":1,"nodeName":if new_tab {"A"} else {"BUTTON"},"localName":if new_tab {"a"} else {"button"},"attributes":if new_tab {json!(["href","/new","target","_blank"])} else {json!(["type","button"])}},
        {"nodeId":4,"parentId":2,"backendNodeId":4,"nodeType":1,"nodeName":"INPUT","localName":"input","attributes":if payment { json!(["type","text","autocomplete","cc-number"]) } else { json!(["type",if password {"password"} else {"text"}]) }},
        {"nodeId":5,"parentId":2,"backendNodeId":5,"nodeType":1,"nodeName":"INPUT","localName":"input","attributes":["type","password"]}
    ]})
}

fn reference(reply: &Value, name: &str) -> String {
    reply["state_text"]
        .as_str()
        .unwrap()
        .lines()
        .find(|line| line.contains(name))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .into()
}

fn click(tab: &str, snapshot: &Value, reference: &str) -> Value {
    json!({"browser":"user","action":"click","tab":tab,"snapshot_id":snapshot["snapshot_id"],"ref":reference,"intent":"press Go","severity":{"tier":2,"credential":false,"financial":false}})
}

#[tokio::test]
async fn per_site_ask_is_required_and_allow_once_is_one_invocation() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    for _ in 0..2 {
        let (reply, cards) = fixture.snapshot(1, &tab, "allow_once").await;
        assert_eq!(reply["outcome"], "ok", "{reply}");
        assert_eq!(cards.len(), 1, "a skipped per-site ask exposed content");
        let card = &cards[0]["params"];
        assert!(card["prompt"]
            .as_str()
            .unwrap()
            .contains("your own Chrome, signed in as you"));
        assert!(!card.to_string().contains("all_sites"));
        assert!(!reply["state_text"]
            .as_str()
            .unwrap()
            .contains("secret-value"));
        assert!(!reply["state_text"].as_str().unwrap().contains("FOREIGN"));
    }
    assert_eq!(fixture.state.lock().unwrap().captures, vec!["main", "main"]);
}

#[tokio::test]
async fn open_navigate_snapshot_never_launches_an_owned_browser() {
    let fixture = Fixture::new();
    let (opened, _) = fixture
        .call(
            1,
            json!({"browser":"user","action":"open_tab"}),
            "allow_once",
        )
        .await;
    assert_eq!(opened["outcome"], "ok", "{opened}");
    let tab = opened["tab"].as_str().unwrap();
    let (navigated, cards) = fixture.call(1, json!({"browser":"user","action":"navigate","tab":tab,"url":"https://example.com/","intent":"read","wait":"settle","severity":{"tier":1,"credential":false,"financial":false}}), "allow_once").await;
    assert_eq!(navigated["outcome"], "ok", "{navigated}");
    assert_eq!(navigated["settled"], false);
    assert!(navigated["remedy"]
        .as_str()
        .unwrap()
        .contains("Read the page before acting"));
    assert_eq!(cards.len(), 1);
    let (snapshot, cards) = fixture.snapshot(1, tab, "allow_once").await;
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    assert_eq!(cards.len(), 1);
    assert!(!fixture
        .state
        .lock()
        .unwrap()
        .commands
        .iter()
        .any(|command| command["action"] == "launch"));
}

#[tokio::test]
async fn outside_group_tab_is_refused_before_any_cdp_command() {
    let fixture = Fixture::new();
    let (status, _) = fixture
        .call(1, json!({"browser":"user","action":"status"}), "allow_once")
        .await;
    assert_eq!(status["tabs"].as_array().unwrap().len(), 1);
    assert_eq!(status["tabs"][0]["tab"], "handed");
    let before = fixture.state.lock().unwrap().commands.len();
    let (reply, cards) = fixture.snapshot(1, "outside", "allow_once").await;
    assert_eq!(reply["reason"], "tab_not_claimed_by_route");
    assert!(cards.is_empty());
    assert_eq!(
        fixture.state.lock().unwrap().commands.len(),
        before,
        "outside-group action reached the bridge"
    );
}

#[tokio::test]
async fn handed_tab_claims_refs_and_snapshots_are_route_tab_and_epoch_scoped() {
    let fixture = Fixture::new();
    let (unclaimed, _) = fixture.snapshot(1, "handed", "allow_once").await;
    assert_eq!(unclaimed["reason"], "tab_not_claimed_by_route");
    let tab = fixture.claim(1).await;
    let (held, _) = fixture
        .call(
            2,
            json!({"browser":"user","action":"claim_tab","tab":tab}),
            "allow_once",
        )
        .await;
    assert_eq!(held["reason"], "tab_already_claimed");
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_once").await;
    let reference = reference(&snapshot, "Go");
    let (other, _) = fixture
        .call(
            2,
            json!({"browser":"user","action":"open_tab"}),
            "allow_once",
        )
        .await;
    let other_tab = other["tab"].as_str().unwrap();
    let (reused, _) = fixture
        .call(2, click(other_tab, &snapshot, &reference), "allow_once")
        .await;
    assert_eq!(reused["reason"], "snapshot_scope_mismatch");
    let mut own_ref = click(&tab, &snapshot, "own-ref");
    own_ref["snapshot_id"] = json!("own-snapshot");
    let (refused, _) = fixture.call(1, own_ref, "allow_once").await;
    assert_eq!(refused["reason"], "snapshot_scope_mismatch");
    fixture
        .planes
        .user_browser
        .disconnect_for_policy_test(fixture.epoch);
    assert!(fixture
        .planes
        .user_browser
        .target()
        .state()
        .snapshots
        .is_empty());
    assert!(fixture.state.lock().unwrap().inputs.is_empty());
}

#[tokio::test]
async fn own_and_user_standing_grants_are_isolated_in_both_directions() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let facts = fixture.planes.routes.get(1, 1).unwrap();
    let own = fixture.planes.management.standing_browser_grants();
    // This agent-profile StandingBrowserGrants fixture has no machine identity,
    // so it cannot record persistent site consent. Install a conversation-only
    // ActionGrant in the agent-profile GrantStore to prove that it cannot
    // authorize the person's Chrome.
    fixture
        .planes
        .management
        .browser_grants()
        .lock()
        .await
        .replace(authorization::ActionGrant::for_conversation(
            "own-only",
            1,
            facts.identity.conversation_key.clone(),
            Severity::new(4, true, true),
            ["https://example.com"],
        ))
        .unwrap();
    let (denied, cards) = fixture.snapshot(1, &tab, "deny").await;
    assert_eq!(denied["reason"], "consent_declined");
    assert_eq!(cards.len(), 1);
    assert!(fixture.state.lock().unwrap().captures.is_empty());
    let (allowed, cards) = fixture.snapshot(1, &tab, "allow_origin_always").await;
    assert_eq!(allowed["outcome"], "ok", "{allowed}");
    assert_eq!(cards.len(), 1);
    assert!(own.live_rows(&facts.identity.agent_project_id).is_empty());
    let (_, cards) = fixture.snapshot(1, &tab, "deny").await;
    assert!(cards.is_empty(), "user standing grant was not used");
    let (revoked, _) = fixture
        .call(
            1,
            json!({"browser":"user","action":"revoke_access","origin":"https://example.com"}),
            "deny",
        )
        .await;
    assert_eq!(revoked["browser"], "user");
    assert_eq!(
        fixture.planes.management.browser_grant_count().await,
        1,
        "user revoke touched own grants"
    );
    let (_, cards) = fixture.snapshot(1, &tab, "deny").await;
    assert_eq!(cards.len(), 1);
}

#[tokio::test]
async fn redirect_to_ungranted_landing_site_exposes_no_content() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    fixture.state.lock().unwrap().redirect = Some("https://ungranted.example/private".into());
    let (reply, cards) = fixture.call(1, json!({"browser":"user","action":"navigate","tab":tab,"url":"https://example.com/go","intent":"read","severity":{"tier":1,"credential":false,"financial":false},"read_page":true}), "allow_once").await;
    assert_eq!(reply["reason"], "landing_site_not_authorized");
    assert_eq!(cards.len(), 1);
    assert!(reply.get("read_page").is_none());
    assert!(reply.get("state_text").is_none());
    assert!(fixture.state.lock().unwrap().captures.is_empty());
}

#[tokio::test]
async fn human_input_before_dispatch_and_between_steps_stops_all_further_input() {
    for before in [true, false] {
        let fixture = Fixture::new();
        let tab = fixture.claim(1).await;
        let (snapshot, _) = fixture.snapshot(1, &tab, "allow_origin_always").await;
        let reference = reference(&snapshot, "Go");
        {
            let mut state = fixture.state.lock().unwrap();
            state.human_before_input = before;
            state.human_after_input = !before;
        }
        let (reply, _) = fixture
            .call(1, click(&tab, &snapshot, &reference), "allow_once")
            .await;
        assert_eq!(reply["reason"], "state_changed_by_person", "{reply}");
        assert_eq!(reply["remedy"], "read again");
        assert_eq!(reply["input_dispatched"], !before);
        assert_eq!(
            fixture.state.lock().unwrap().inputs.len(),
            usize::from(!before)
        );
        let (fresh, _) = fixture.snapshot(1, &tab, "allow_origin_always").await;
        let fresh_reference = fresh["state_text"]
            .as_str()
            .unwrap()
            .lines()
            .find(|line| line.contains("Go"))
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap();
        let (success, _) = fixture
            .call(1, click(&tab, &fresh, fresh_reference), "allow_once")
            .await;
        assert_eq!(success["outcome"], "ok", "{success}");
    }
}

#[tokio::test]
async fn detached_human_input_and_reconnect_never_refresh_a_refused_baseline() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_once").await;
    let reference = reference(&snapshot, "Go");
    fixture
        .state
        .lock()
        .unwrap()
        .tabs
        .get_mut(&tab)
        .unwrap()
        .interaction += 1;
    for _ in 0..2 {
        let (reply, _) = fixture
            .call(1, click(&tab, &snapshot, &reference), "allow_once")
            .await;
        assert_eq!(reply["reason"], "state_changed_by_person");
    }
    assert!(fixture.state.lock().unwrap().inputs.is_empty());
    fixture
        .planes
        .user_browser
        .disconnect_for_policy_test(fixture.epoch);
    let (reply, _) = fixture
        .call(1, click(&tab, &snapshot, &reference), "allow_once")
        .await;
    assert_eq!(reply["reason"], "not_connected");
    assert_eq!(reply["browser"], "user");
}

#[tokio::test]
async fn close_and_goodbye_release_without_closing_any_person_tab() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let (reply, _) = fixture
        .call(1, json!({"browser":"user","action":"close"}), "allow_once")
        .await;
    assert_eq!(reply["outcome"], "closed");
    assert!(fixture
        .planes
        .user_browser
        .target()
        .state()
        .claims
        .is_empty());
    assert_eq!(fixture.state.lock().unwrap().tabs.len(), 2);
    assert!(fixture.state.lock().unwrap().tabs.contains_key("outside"));
    assert!(!fixture.state.lock().unwrap().tabs[&tab].group);
    let (opened, _) = fixture
        .call(
            1,
            json!({"browser":"user","action":"open_tab"}),
            "allow_once",
        )
        .await;
    fixture.planes.user_browser.goodbye(Route {
        channel: 1,
        epoch: 1,
    });
    assert!(fixture
        .planes
        .user_browser
        .target()
        .state()
        .claims
        .is_empty());
    assert!(fixture
        .state
        .lock()
        .unwrap()
        .tabs
        .contains_key(opened["tab"].as_str().unwrap()));
}

#[tokio::test]
async fn credential_payment_typing_refuses_and_normal_typing_uses_background_focus() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_once").await;
    let password = reference(&snapshot, "Password");
    let (refused, _) = fixture.call(1, json!({"browser":"user","action":"type","tab":tab,"ref":password,"text":"do not persist this"}), "allow_once").await;
    assert_eq!(
        refused["reason"], "credential_payment_or_ineligible_field",
        "{refused}"
    );
    assert!(fixture.state.lock().unwrap().inputs.is_empty());
    let text = reference(&snapshot, "Message");
    let (typed, _) = fixture.call(1, json!({"browser":"user","action":"type","tab":tab,"ref":text,"text":"do not persist this","clear_first":true}), "allow_once").await;
    assert_eq!(typed["outcome"], "ok", "{typed}");
    let journal = fixture.planes.browser.journal_export_for_test().await;
    assert!(journal.contains("\"browser\":\"user\""));
    assert!(!journal.contains("do not persist this"));
    assert!(!journal.contains("secret-value"));
    assert!(!journal.contains("/private"));
    assert!(fixture
        .state
        .lock()
        .unwrap()
        .commands
        .iter()
        .flat_map(|plan| plan["commands"].as_array().into_iter().flatten())
        .any(|command| command["method"] == "Emulation.setFocusEmulationEnabled"));
}

#[tokio::test]
async fn explicit_new_tab_links_are_background_opens_and_script_popup_flags_surface() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    fixture.state.lock().unwrap().new_tab_link = true;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_origin_always").await;
    let (reply, _) = fixture
        .call(
            1,
            click(&tab, &snapshot, &reference(&snapshot, "Go")),
            "allow_once",
        )
        .await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_ne!(reply["tab"], tab);
    assert!(fixture.state.lock().unwrap().inputs.is_empty());
    assert!(fixture
        .state
        .lock()
        .unwrap()
        .commands
        .iter()
        .any(|command| command["action"] == "open_tab"
            && command["opener_tab"] == tab
            && command["url"] == "https://example.com/new"));
    fixture.state.lock().unwrap().new_tab_link = false;
    fixture.state.lock().unwrap().popup = true;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_origin_always").await;
    let (reply, _) = fixture
        .call(
            1,
            click(&tab, &snapshot, &reference(&snapshot, "Go")),
            "allow_once",
        )
        .await;
    assert_eq!(reply["popup_activated_briefly"], true, "{reply}");
}

#[tokio::test]
async fn own_success_and_refusal_bytes_match_omitted_and_explicit_own() {
    let fixture = Fixture::new();
    for args in [
        json!({"action":"status"}),
        json!({"action":"snapshot"}),
        json!({"action":"navigate"}),
    ] {
        let (omitted, _) = fixture.call(1, args.clone(), "deny").await;
        let mut explicit = args;
        explicit["browser"] = json!("own");
        let (own, _) = fixture.call(1, explicit, "deny").await;
        assert_eq!(
            serde_json::to_vec(&omitted).unwrap(),
            serde_json::to_vec(&own).unwrap()
        );
        assert!(own.get("browser").is_none());
    }
    for action in ["open_tab", "claim_tab"] {
        let (reply, _) = fixture
            .call(1, json!({"action":action,"browser":"own"}), "deny")
            .await;
        assert_eq!(reply["outcome"], "invalid_request");
        assert_eq!(reply["detail"]["reason_code"], "unsupported_value");
    }
    let (reply, _) = fixture
        .call(1, json!({"action":"launch","browser":"user"}), "deny")
        .await;
    assert_eq!(reply["reason"], "unsupported_action");
    assert!(reply["remedy"]
        .as_str()
        .unwrap()
        .contains("open_tab or claim_tab"));
}

#[tokio::test]
async fn group_removal_while_consent_is_pending_returns_no_content_or_input() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    fixture.state.lock().unwrap().remove_group_on_card = true;
    let (reply, cards) = fixture.snapshot(1, &tab, "allow_once").await;
    assert_eq!(cards.len(), 1);
    assert_eq!(reply["reason"], "outside_agent_group");
    assert!(fixture.state.lock().unwrap().captures.is_empty());
    assert!(fixture.state.lock().unwrap().inputs.is_empty());
    assert!(reply.get("state_text").is_none());
}

#[tokio::test]
async fn screenshot_points_use_echoed_pixels_and_refuse_changed_viewports_and_frames() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let (image, _) = fixture
        .call(
            1,
            json!({"browser":"user","action":"screenshot","tab":tab}),
            "allow_once",
        )
        .await;
    assert_eq!(image["outcome"], "ok", "{image}");
    assert_eq!(image["image_width_px"], 1);
    let point = json!({"browser":"user","action":"click_point","tab":tab,"snapshot_id":image["snapshot_id"],"point":{"x":0,"y":0},"image_width_px":1,"image_height_px":1,"intent":"click","severity":{"tier":2,"credential":false,"financial":false}});
    let (clicked, _) = fixture.call(1, point.clone(), "allow_once").await;
    assert_eq!(clicked["outcome"], "ok", "{clicked}");
    {
        let state = fixture.state.lock().unwrap();
        let sent = state
            .commands
            .iter()
            .flat_map(|plan| plan["commands"].as_array().into_iter().flatten())
            .find(|command| command["method"] == "Input.dispatchMouseEvent")
            .unwrap();
        assert_eq!(sent["params"]["x"], 50.0);
    }
    fixture.state.lock().unwrap().inputs.clear();
    fixture.state.lock().unwrap().foreign_hit = true;
    let before = fixture.state.lock().unwrap().commands.len();
    let (foreign, cards) = fixture.call(1, point.clone(), "allow_once").await;
    assert!(cards.is_empty());
    assert!(!fixture.state.lock().unwrap().commands[before..]
        .iter()
        .flat_map(|plan| plan["commands"].as_array().into_iter().flatten())
        .any(|command| command["method"]
            .as_str()
            .is_some_and(|method| method.starts_with("Input."))));
    assert_eq!(foreign["reason"], "embedded_frame_unsupported");
    assert!(foreign["remedy"]
        .as_str()
        .unwrap()
        .contains("cannot be used"));
    assert!(fixture.state.lock().unwrap().inputs.is_empty());
    fixture.state.lock().unwrap().viewport_changed = true;
    let (changed, _) = fixture.call(1, point, "allow_once").await;
    assert_eq!(changed["reason"], "viewport_changed");
    assert!(fixture.state.lock().unwrap().inputs.is_empty());
}

#[tokio::test]
async fn screenshot_returns_a_liftable_image_object_without_flat_base64() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let (reply, _) = fixture
        .call(
            1,
            json!({"browser":"user","action":"screenshot","tab":tab}),
            "allow_once",
        )
        .await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(reply["image"]["mime"], "image/png");
    assert_eq!(reply["image"]["data_b64"], "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==");
    assert_eq!(reply["image"]["width_px"], reply["image_width_px"]);
    assert_eq!(reply["image"]["height_px"], reply["image_height_px"]);
    assert!(reply.get("image_png_b64").is_none());
    assert!(crate::browser::validate_user_browser_result("screenshot", &reply).is_ok());
    let mut flat = reply;
    let image = flat.as_object_mut().unwrap().remove("image").unwrap();
    flat["image_png_b64"] = image["data_b64"].clone();
    assert!(crate::browser::validate_user_browser_result("screenshot", &flat).is_err());
}

#[tokio::test]
async fn new_tab_actions_have_exactly_launch_admission_and_user_refusals_are_tagged() {
    let admitted = vec![crate::browser_session::BROWSER_STATUS.to_owned()];
    let tool = crate::flat_tools::browser_tool(&admitted).unwrap();
    for action in ["launch", "open_tab", "claim_tab"] {
        assert!(!tool.schema["properties"]["action"]["enum"]
            .as_array()
            .unwrap()
            .contains(&json!(action)));
    }
    assert_eq!(
        crate::flat_tools::browser_capability("open_tab"),
        Some(crate::browser_session::BROWSER_LAUNCH)
    );
    assert_eq!(
        crate::flat_tools::browser_capability("claim_tab"),
        Some(crate::browser_session::BROWSER_LAUNCH)
    );
    let fixture = Fixture::new();
    let mut facts = fixture.planes.routes.get(1, 1).unwrap();
    facts
        .control_operations
        .retain(|capability| capability != crate::browser_session::BROWSER_LAUNCH);
    fixture.planes.routes.insert(1, 1, facts);
    let (launch, _) = fixture.call(1, json!({"action":"launch"}), "deny").await;
    for action in ["open_tab", "claim_tab"] {
        let (mut reply, _) = fixture
            .call(
                1,
                json!({"action":action,"browser":"user","tab":"handed"}),
                "deny",
            )
            .await;
        assert_eq!(reply["browser"], "user");
        reply.as_object_mut().unwrap().remove("browser");
        assert_eq!(reply, launch);
    }
    let (invalid, _) = fixture
        .call(1, json!({"browser":"user","action":"unknown"}), "deny")
        .await;
    assert_eq!(invalid["browser"], "user");
    assert_eq!(invalid["outcome"], "invalid_request");
    assert!(fixture.state.lock().unwrap().commands.is_empty());
}

#[tokio::test]
async fn payment_field_typing_is_hard_refused_even_with_site_consent() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    fixture.state.lock().unwrap().payment = true;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_origin_always").await;
    let (reply, _) = fixture.call(1, json!({"browser":"user","action":"type","tab":tab,"ref":reference(&snapshot,"Message"),"text":"4111"}), "allow_once").await;
    assert_eq!(
        reply["reason"], "credential_payment_or_ineligible_field",
        "{reply}"
    );
    assert!(fixture.state.lock().unwrap().inputs.is_empty());
}

#[test]
fn late_snapshot_results_cannot_restore_goodbye_handles_or_cross_connection_refs() {
    let target = UserBrowser::new(Arc::new(StandingBrowserGrants::in_memory()));
    let route = Route {
        channel: 1,
        epoch: 1,
    };
    target.synchronize(7);
    let snapshot = Snapshot {
        route,
        tab: "t".into(),
        connection: 7,
        interaction: 1,
        document: CommittedDocument::new("https://example.com/", 1, "l"),
        refs: BTreeMap::new(),
        image: None,
    };
    target.end_route(route);
    target.retain("late".into(), snapshot.clone());
    assert!(target.state().snapshots.is_empty());
    target.synchronize(8);
    target.retain("old-connection".into(), snapshot);
    assert!(target.state().snapshots.is_empty());
}

#[test]
fn user_result_envelopes_are_closed_and_target_tagged() {
    let valid = json!({"browser":"user","outcome":"ok","tab":"t","state_text":"page","snapshot_id":"s","interaction_epoch":1,"connection_epoch":7});
    assert!(crate::browser::validate_user_browser_result("snapshot", &valid).is_ok());
    let mut invalid = valid.clone();
    invalid["undeclared"] = json!(true);
    assert!(crate::browser::validate_user_browser_result("snapshot", &invalid).is_err());
    let mut untagged = valid;
    untagged.as_object_mut().unwrap().remove("browser");
    assert!(crate::browser::validate_user_browser_result("snapshot", &untagged).is_err());
}

#[tokio::test]
async fn user_browser_typing_never_sends_text_key_events() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_once").await;
    let (reply, _) = fixture.call(1, json!({"browser":"user","action":"type","tab":tab,"ref":reference(&snapshot,"Message"),"text":"hello","clear_first":true}), "allow_once").await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    let state = fixture.state.lock().unwrap();
    let commands: Vec<_> = state
        .commands
        .iter()
        .flat_map(|plan| plan["commands"].as_array().into_iter().flatten())
        .collect();
    assert_eq!(
        commands
            .iter()
            .filter(|command| command["method"] == "Input.insertText"
                && command["params"]["text"] == "hello")
            .count(),
        1,
        "text must be inserted by the attributed CDP method"
    );
    for command in commands {
        if command["method"] == "Input.dispatchKeyEvent" {
            assert!(
                command["params"].get("text").is_none()
                    && command["params"].get("unmodifiedText").is_none(),
                "text-bearing key events cannot be attributed to the agent"
            );
        }
    }
}

#[tokio::test]
async fn user_target_preserves_unattended_flow_admission() {
    let fixture = Fixture::new();
    let mut facts = fixture.planes.routes.get(1, 1).unwrap();
    facts.flow_id = Some("flow".into());
    facts.acts_as_agent = false;
    fixture.planes.routes.insert(1, 1, facts);
    let (reply, cards) = fixture
        .call(
            1,
            json!({"browser":"user","action":"open_tab"}),
            "allow_once",
        )
        .await;
    assert_eq!(reply["browser"], "user");
    assert_eq!(reply["outcome"], "consent_unavailable");
    assert_eq!(reply["detail"]["reason"], "unattended_flow");
    assert!(cards.is_empty());
    assert!(fixture.state.lock().unwrap().commands.is_empty());
}

#[tokio::test]
async fn popup_reports_from_metadata_plans_survive_terminal_refusals() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    fixture.state.lock().unwrap().popup_once_on_metadata = true;
    let (reply, cards) = fixture.snapshot(1, &tab, "deny").await;
    assert_eq!(cards.len(), 1);
    assert_eq!(reply["reason"], "consent_declined");
    assert_eq!(
        reply["popup_activated_briefly"], true,
        "the initial metadata plan's popup must remain visible on the refusal"
    );
    assert!(fixture.state.lock().unwrap().inputs.is_empty());
    assert!(fixture.state.lock().unwrap().captures.is_empty());
}

#[tokio::test]
async fn typing_consumes_remote_objects_in_the_same_plan_that_resolves_them() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_once").await;
    let (reply, _) = fixture.call(1, json!({"browser":"user","action":"type","tab":tab,"ref":reference(&snapshot,"Message"),"text":"hello","clear_first":true}), "allow_once").await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    let state = fixture.state.lock().unwrap();
    let mut functions = 0;
    for plan in &state.commands {
        let Some(commands) = plan["commands"].as_array() else {
            continue;
        };
        for (index, command) in commands.iter().enumerate() {
            assert_eq!(
                command["frame_id"], 0,
                "CDP ids are not webNavigation sentinel ids"
            );
            if command["method"] == "Runtime.callFunctionOn" {
                functions += 1;
                let object = &command["params"]["objectId"];
                assert!(
                    !object.is_string(),
                    "a remote object id must not outlive debugger detach"
                );
                let source = object["$result"].as_u64().unwrap() as usize;
                assert!(source < index);
                assert_eq!(commands[source]["method"], "DOM.resolveNode");
                assert_eq!(object["path"], json!(["object", "objectId"]));
            }
        }
    }
    assert!(
        functions >= 2,
        "selection and focus checks must actually execute"
    );
}

#[tokio::test]
async fn embedded_frames_are_explicitly_omitted_without_text_or_refs() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_once").await;
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    assert_eq!(snapshot["omitted_frames"], 1);
    assert!(snapshot["frame_note"]
        .as_str()
        .unwrap()
        .contains("cannot be used"));
    assert!(!snapshot["state_text"].as_str().unwrap().contains("FOREIGN"));
    let state = fixture.planes.user_browser.target().state();
    let retained = state
        .snapshots
        .get(snapshot["snapshot_id"].as_str().unwrap())
        .unwrap();
    assert!(!retained.refs.is_empty());
    assert!(
        retained
            .refs
            .values()
            .all(|reference| reference.frame.parent_id.is_none()
                && reference.frame.frame_id == "main")
    );
}

#[tokio::test]
async fn authority_changing_severity_is_never_grantable_in_the_user_browser() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_once").await;
    let mut request = click(&tab, &snapshot, &reference(&snapshot, "Go"));
    request["severity"]["tier"] = json!(5);
    let (reply, cards) = fixture.call(1, request, "allow_once").await;
    assert_eq!(reply["reason"], "severity_ungrantable");
    assert!(cards.is_empty());
    assert!(fixture.state.lock().unwrap().inputs.is_empty());
}
