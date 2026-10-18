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

use crate::cingulate_client::desk::FileRegistryStore;
use crate::cingulate_client::live_call::LiveCall;
use crate::cingulate_client::route::{BoxFuture, CallError, CingulateOpener, CingulateRoute};
use crate::cingulate_client::wire;
use crate::cingulate_client::{Reply, ScriptedCingulate};
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
    /// Chrome's CDP error for the next plan command with this method.
    fail_method: Option<(&'static str, i64, String)>,
    /// The "Go" button has no type attribute and no form, like the button in
    /// the real-Chrome probe's page (examples/user_browser_probe.rs). A
    /// `<button>` defaults to type submit, so this checks that a submit-type
    /// control without a form owner is not rated as a form submit.
    untyped_button: bool,
    ax_override: Option<Value>,
    top_level_only: bool,
    unmapped_child_owner: bool,
    same_origin_child: bool,
    ambiguous_frames: bool,
    frame_pair: bool,
    stray_navigation: bool,
    stale_root_mapping: bool,
    moving_child: bool,
    child_loader: u64,
    child_ax_unavailable: bool,
    child_ax_oversized: bool,
    plan_delay: Duration,
    consent_delay: Duration,
    plan_count: usize,
    attaches: usize,
    hang_plan: Option<usize>,
    hang_action: Option<&'static str>,
    hang_attach: bool,
    ignore_cancel: bool,
    stop_after_plan: Option<usize>,
    cancel_on_stop: bool,
    terminal: Option<Arc<crate::TerminalArbiter>>,
}

/// Cingulate as the site-card tests need it: every card is answered at once
/// with the choice the current call was given, and the cards it was sent are
/// kept for the tests to read. A withdrawn card reads as withdrawn.
struct SiteCingulate {
    state: Arc<Mutex<DoubleState>>,
    decision: Mutex<String>,
    cards: Mutex<Vec<Value>>,
}

struct SiteCingulateRoute(Arc<SiteCingulate>);

impl CingulateOpener for Arc<SiteCingulate> {
    fn open<'a>(
        &'a self,
        _live: &'a LiveCall,
    ) -> BoxFuture<'a, Result<Box<dyn CingulateRoute>, CallError>> {
        let route = SiteCingulateRoute(Arc::clone(self));
        Box::pin(async move { Ok(Box::new(route) as Box<dyn CingulateRoute>) })
    }
}

impl CingulateRoute for SiteCingulateRoute {
    fn call<'a>(
        &'a mut self,
        method: &'a str,
        params: Value,
    ) -> BoxFuture<'a, Result<Value, CallError>> {
        Box::pin(async move {
            let id = params["elicitation_id"].clone();
            match method {
                wire::CONSENT_REQUEST => {
                    let mut cards = self.0.cards.lock().unwrap();
                    cards.push(params);
                    let mut state = self.0.state.lock().unwrap();
                    if state.remove_group_on_card {
                        state.remove_group_on_card = false;
                        state.tabs.get_mut("handed").unwrap().group = false;
                    }
                    Ok(json!({"elicitation_id": format!("el_site_{}", cards.len())}))
                }
                wire::CONSENT_AWAIT => {
                    let delay = self.0.state.lock().unwrap().consent_delay;
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    let choice = self.0.decision.lock().unwrap().clone();
                    Ok(json!({"elicitation_id":id,"state":"answered","answered_choice_id":choice}))
                }
                wire::CONSENT_WITHDRAW => Ok(json!({"elicitation_id":id,"state":"withdrawn"})),
                wire::CONSENT_REPORT_EXECUTION => Ok(
                    json!({"elicitation_id":id,"state":"answered","execution":params["execution"]}),
                ),
                _ => panic!("a site card made an unexpected Cingulate call: {method}"),
            }
        })
    }
}

struct Fixture {
    planes: Arc<Planes>,
    state: Arc<Mutex<DoubleState>>,
    site: Arc<SiteCingulate>,
    registry: std::path::PathBuf,
    epoch: u64,
    corr: AtomicU64,
    worker: tokio::task::JoinHandle<()>,
}

/// A call started with [`Fixture::start`] and still running.
struct Started {
    corr: u64,
    replies: mpsc::Receiver<Frame>,
    task: tokio::task::JoinHandle<()>,
}

impl Fixture {
    fn new() -> Self {
        Self::with_cingulate(None)
    }

    /// A fixture whose site cards go to `script` instead of the answering
    /// [`SiteCingulate`].
    fn scripted(script: &Arc<ScriptedCingulate>) -> Self {
        Self::with_cingulate(Some(Arc::new(Arc::clone(script))))
    }

    fn with_cingulate(opener: Option<Arc<dyn CingulateOpener>>) -> Self {
        Self::with_agent_grants(
            opener,
            Some(Arc::new(crate::agent_grants::AgentGrants::in_memory(Some(
                "test-machine".into(),
            )))),
        )
    }

    fn with_agent_grants(
        opener: Option<Arc<dyn CingulateOpener>>,
        agent_grants: Option<Arc<crate::agent_grants::AgentGrants>>,
    ) -> Self {
        Self::with_stores(opener, agent_grants, true)
    }

    fn with_stores(
        opener: Option<Arc<dyn CingulateOpener>>,
        agent_grants: Option<Arc<crate::agent_grants::AgentGrants>>,
        recordable_user_store: bool,
    ) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let registry = std::env::temp_dir().join(format!(
            "user-browser-cards-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&registry).unwrap();
        let state = Arc::new(Mutex::new(DoubleState::default()));
        let site = Arc::new(SiteCingulate {
            state: Arc::clone(&state),
            decision: Mutex::new(String::new()),
            cards: Mutex::new(Vec::new()),
        });
        let opener = opener.unwrap_or_else(|| Arc::new(Arc::clone(&site)));
        let mut planes =
            crate::isolated_test_planes(&Arc::new(cerebellum_core::health::HealthState::new()))
                .with_cingulate(
                    opener,
                    Arc::new(FileRegistryStore::new(registry.join("registry.json"))),
                );
        if recordable_user_store {
            let grants = Arc::new(StandingBrowserGrants::open(
                Arc::new(crate::browser_standing_grants::InMemoryStandingGrantStorage::new()),
                Some("test-machine".into()),
            ));
            planes.user_browser = UserBrowserBridge::with_user_grants(grants);
        }
        if let Some(grants) = agent_grants {
            planes.management = Arc::new(
                crate::management::ManagementPlane::new(Arc::new(
                    crate::management::PlatformResolver::new(),
                ))
                .with_agent_grants(grants),
            );
        }
        let planes = Arc::new(planes);
        for channel in [1, 2] {
            let frame = tool_frame(channel, 1, json!({"action":"status"}));
            crate::install_test_bind(&planes.routes, &frame);
            let mut facts = planes.routes.get(channel, 1).unwrap();
            facts = facts.with_scope(Some(crate::computer_grants::tests::stamp("test-project")));
            planes.routes.insert(channel, 1, facts);
        }
        let (epoch, mut commands) = planes.user_browser.connect_for_policy_test();
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
                if !bridge.should_send(&message) {
                    continue;
                }
                match message.body {
                    MessageBody::Attach { route, command } => {
                        worker_state.lock().unwrap().attaches += 1;
                        pending.insert(message.id, (route, command));
                        if worker_state.lock().unwrap().hang_attach {
                            continue;
                        }
                        bridge.receive_for_policy_test(Message {
                            id: message.id,
                            epoch,
                            body: MessageBody::Attached,
                        });
                    }
                    MessageBody::Dispatch => {
                        let (route, command) = pending.remove(&message.id).unwrap();
                        let mut state = worker_state.lock().unwrap();
                        let cdp = command["action"] == "cdp";
                        if cdp {
                            state.plan_count += 1;
                        }
                        let hanging = (cdp && state.hang_plan == Some(state.plan_count))
                            || state.hang_action == command["action"].as_str();
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
                        if cdp && state.stop_after_plan == Some(state.plan_count) {
                            state
                                .terminal
                                .as_ref()
                                .unwrap()
                                .stop(if state.cancel_on_stop {
                                    crate::TerminalCause::Cancelled
                                } else {
                                    crate::TerminalCause::Deadline
                                });
                        }
                        if !hanging {
                            let bridge = bridge.clone();
                            let delay = if cdp {
                                state.plan_delay
                            } else {
                                Duration::ZERO
                            };
                            let reply = Message {
                                id: message.id,
                                epoch,
                                body,
                            };
                            if delay.is_zero() {
                                bridge.receive_for_policy_test(reply);
                            } else {
                                tokio::spawn(async move {
                                    tokio::time::sleep(delay).await;
                                    bridge.receive_for_policy_test(reply);
                                });
                            }
                        }
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
                        if worker_state.lock().unwrap().ignore_cancel {
                            continue;
                        }
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
            site,
            registry,
            epoch,
            corr: AtomicU64::new(10),
            worker,
        }
    }

    /// Send one tool call on `channel`, its site cards answered `decision`,
    /// without waiting for its reply.
    fn start(&self, channel: u16, args: Value, decision: &str) -> Started {
        *self.site.decision.lock().unwrap() = decision.into();
        let corr = self.corr.fetch_add(1, Ordering::Relaxed);
        let frame = tool_frame(channel, corr, args);
        let registration = self.planes.cancellations.register((channel, 1, corr));
        let (writer, replies) = mpsc::channel(16);
        let planes = self.planes.clone();
        let arrival = crate::browser_queue::arrive(&frame, &planes);
        // `with_live` puts an in-flight guard in scope, as the frame loop does
        // for a real call; the consent desk opens a route to Cingulate only
        // while such a guard shows the call is still held.
        let task = tokio::spawn(crate::computer_grants::tests::with_live(async move {
            let _registration = registration;
            crate::browser_queue::scope(
                arrival,
                crate::handle_route_request(frame, &writer, &planes),
            )
            .await
            .unwrap();
        }));
        Started {
            corr,
            replies,
            task,
        }
    }

    // Run the production handler under the frame loop's terminal arbiter. Keep
    // its handle so the scripted extension can stop dispatch between plans.
    fn start_arbitrated(&self, args: Value) -> Started {
        self.start_arbitrated_with_limit(
            args,
            Duration::from_millis(crate::budgets::BROWSER_ENVELOPE_MS),
        )
    }

    fn start_arbitrated_with_limit(&self, args: Value, limit: Duration) -> Started {
        *self.site.decision.lock().unwrap() = "allow_30m".into();
        let corr = self.corr.fetch_add(1, Ordering::Relaxed);
        let frame = tool_frame(1, corr, args);
        let terminal = Arc::new(crate::TerminalArbiter::new(frame.clone()));
        self.state.lock().unwrap().terminal = Some(Arc::clone(&terminal));
        let registration = self.planes.cancellations.register((1, 1, corr));
        *registration.handle.0.terminal.lock().unwrap() = Some(Arc::downgrade(&terminal));
        let (writer, replies) = mpsc::channel(16);
        let (proxy, outgoing) = mpsc::channel(16);
        let planes = self.planes.clone();
        let worker_planes = Arc::clone(&planes);
        let arrival = crate::browser_queue::arrive(&frame, &planes);
        let guard = Arc::new(planes.health.enter_request());
        let now = tokio::time::Instant::now();
        let task = tokio::spawn(crate::terminal_arbiter::run_arbitrated_route(
            Box::pin(async move {
                crate::browser_queue::scope(
                    arrival,
                    crate::handle_route_request(frame, &proxy, &worker_planes),
                )
                .await
            }),
            outgoing,
            writer,
            (*planes).clone(),
            registration,
            guard,
            terminal,
            now + limit,
            now + Duration::from_millis(crate::budgets::BROWSER_REPLY_MAX_MS),
        ));
        Started {
            corr,
            replies,
            task,
        }
    }

    /// The reply to a started call. Nothing but the reply may reach the
    /// call's route: no consent question travels back along it.
    async fn finish(&self, mut started: Started) -> Value {
        let frame = tokio::time::timeout(Duration::from_secs(5), started.replies.recv())
            .await
            .expect("bounded tool invocation")
            .expect("tool response");
        assert!(
            matches!(
                frame.header.ty,
                subc_protocol::FrameType::Response | subc_protocol::FrameType::Error
            ),
            "a frame other than the reply reached the route: {:?}",
            frame.header.ty
        );
        assert_eq!(frame.header.corr, started.corr);
        started.task.await.unwrap();
        assert!(
            started.replies.try_recv().is_err(),
            "more than one frame reached the route"
        );
        serde_json::from_slice(&frame.body).unwrap()
    }

    /// One tool call, its site cards answered `decision`: the reply and the
    /// cards (`consent.request` params) it raised.
    async fn call(&self, channel: u16, args: Value, decision: &str) -> (Value, Vec<Value>) {
        let before = self.site.cards.lock().unwrap().len();
        let started = self.start(channel, args, decision);
        let response = self.finish(started).await;
        let cards = self.site.cards.lock().unwrap()[before..].to_vec();
        (response, cards)
    }

    async fn claim(&self, channel: u16) -> String {
        let (reply, _) = self
            .call(
                channel,
                json!({"browser":"user","action":"claim_tab","tab":"handed"}),
                "allow_30m",
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
        let _ = std::fs::remove_dir_all(&self.registry);
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
    assert_eq!(command["version"], 2);
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
    let child_url = if state.same_origin_child {
        tab.url.clone()
    } else {
        "https://ungranted.example/secret".into()
    };
    let commands = command["commands"].as_array().unwrap();
    if state.moving_child
        && commands
            .iter()
            .any(|command| command["method"] == "Page.getFrameTree")
    {
        state.child_loader += 1;
    }
    let child_loader = if state.moving_child {
        format!("foreign-loader-{}", state.child_loader)
    } else {
        "foreign-loader".into()
    };
    if state.ambiguous_frames
        && commands.iter().any(|command| {
            command["frame_id"]
                .as_str()
                .is_some_and(|id| id.starts_with("pair-"))
        })
    {
        return Err("frame_ambiguous".into());
    }
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
    // Each plan is a fresh debugger attachment, so agents enabled by an
    // earlier plan are disabled again, as in Chrome.
    let mut dom_enabled = false;
    for command in commands {
        let method = command["method"].as_str().unwrap();
        let failure = match &state.fail_method {
            Some((failing, code, message)) if *failing == method => {
                Some(json!({"code":code,"message":message}))
            }
            // Chrome refuses a flattened document before DOM.enable.
            _ if method == "DOM.getFlattenedDocument" && !dom_enabled => {
                Some(json!({"code":-32000,"message":"DOM agent hasn't been enabled"}))
            }
            _ => None,
        };
        if let Some(error) = failure {
            state.fail_method = None;
            // The extension stops a plan at its first CDP error.
            results.push(json!({"error":error}));
            break;
        }
        dom_enabled |= method == "DOM.enable";
        let result = match method {
            "Page.getNavigationHistory" => {
                json!({"currentIndex":0,"entries":[{"id":tab.loader,"url":tab.url}]})
            }
            "Page.getFrameTree" => {
                let mut tree = json!({"frameTree":{"frame":{"id":"main","loaderId":format!("l{}",tab.loader),"url":tab.url},"childFrames":[{"frame":{"id":"foreign","parentId":"main","loaderId":child_loader,"url":child_url}}]}});
                if state.frame_pair {
                    for id in ["pair-one", "pair-two"] {
                        tree["frameTree"]["childFrames"].as_array_mut().unwrap().push(json!({"frame":{"id":id,"parentId":"main","loaderId":"pair-loader","url":"https://pair.example/embedded"}}));
                    }
                }
                if state.top_level_only {
                    tree["frameTree"]
                        .as_object_mut()
                        .unwrap()
                        .remove("childFrames");
                }
                tree
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
                if command["frame_id"] == "foreign" && state.child_ax_unavailable {
                    json!({"nodes":[]})
                } else if command["frame_id"] == "foreign" {
                    let mut ax = json!({"nodes":[
                        {"nodeId":"child-root","ignored":false,"role":{"value":"RootWebArea"},"name":{"value":"Embedded page"},"backendDOMNodeId":1,"frameId":"foreign","childIds":["child-field","child-button"]},
                        {"nodeId":"child-field","ignored":false,"role":{"value":"textbox"},"name":{"value":"Child message"},"value":{"value":"child field value"},"backendDOMNodeId":4},
                        {"nodeId":"child-button","ignored":false,"role":{"value":"button"},"name":{"value":"Child go"},"backendDOMNodeId":3}
                    ]});
                    if state.child_ax_oversized {
                        ax["nodes"][1]["name"]["value"] = json!("X".repeat(8192));
                    }
                    ax
                } else if command["frame_id"]
                    .as_str()
                    .is_some_and(|id| id.starts_with("pair-"))
                {
                    json!({"nodes":[
                        {"nodeId":"pair-root","ignored":false,"role":{"value":"RootWebArea"},"name":{"value":"Pair secret"},"backendDOMNodeId":1,"frameId":command["frame_id"],"childIds":["pair-button"]},
                        {"nodeId":"pair-button","ignored":false,"role":{"value":"button"},"name":{"value":format!("{} button", command["frame_id"].as_str().unwrap())},"backendDOMNodeId":3}
                    ]})
                } else {
                    let mut ax = state.ax_override.clone().unwrap_or_else(ax);
                    // A page with no child documents normally has no iframe
                    // element. Retain that element to simulate a child missing
                    // from discovery but still visible in the parent's AX tree.
                    if state.top_level_only
                        && !state.unmapped_child_owner
                        && state.ax_override.is_none()
                    {
                        ax["nodes"][0]["childIds"] = json!(["button", "text", "secret"]);
                        ax["nodes"].as_array_mut().unwrap().pop();
                    }
                    if state.frame_pair {
                        for (id, backend) in [("pair-one", 7), ("pair-two", 8)] {
                            ax["nodes"][0]["childIds"]
                                .as_array_mut()
                                .unwrap()
                                .push(json!(id));
                            let inline = format!("{id}-inline");
                            ax["nodes"].as_array_mut().unwrap().push(json!({"nodeId":id,"ignored":false,"role":{"value":"Iframe"},"name":{"value":format!("{id} owner")},"backendDOMNodeId":backend,"childIds":[inline]}));
                            ax["nodes"].as_array_mut().unwrap().push(json!({"nodeId":inline,"ignored":false,"role":{"value":"StaticText"},"name":{"value":"UNMAPPABLE_INLINE_SECRET"}}));
                        }
                    }
                    ax
                }
            }
            "DOM.getFlattenedDocument" => {
                let mut dom = dom(
                    state.new_tab_link,
                    state.password,
                    state.payment,
                    state.untyped_button,
                );
                if state.frame_pair {
                    for id in [7, 8] {
                        dom["nodes"].as_array_mut().unwrap().push(json!({"nodeId":id,"parentId":2,"backendNodeId":id,"nodeType":1,"nodeName":"IFRAME","localName":"iframe","attributes":[]}));
                    }
                }
                dom
            }
            "DOM.getContentQuads" => json!({"quads":[[0,0,20,0,20,20,0,20]]}),
            "DOM.getOuterHTML" => {
                json!({"outerHTML":format!("HTML-{}", command["frame_id"].as_str().unwrap())})
            }
            "DOM.getFrameOwner" => {
                json!({"backendNodeId":match command["params"]["frameId"].as_str() { Some("pair-one") => 7, Some("pair-two") => 8, _ => 6 }})
            }
            "DOM.getNodeForLocation" => {
                json!({"backendNodeId":3,"frameId":if state.foreign_hit || command["frame_id"] == "foreign" { "foreign" } else { "main" }})
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
    let mut mappings = vec![
        json!({"frame_id":"main","loader_id":format!("l{}",tab.loader),"session_id":"root","url":tab.url,"web_navigation_frame_id":0,"document_id":format!("main-{}",tab.loader)}),
    ];
    if !state.top_level_only {
        mappings.push(json!({"frame_id":"foreign","parent_id":"main","loader_id":child_loader,"session_id":if state.same_origin_child {"root"} else {"child-target"},"url":child_url,"web_navigation_frame_id":7,"document_id":"child-doc"}));
    }
    if state.frame_pair {
        for (id, web_id) in [("pair-one", 8), ("pair-two", 9)] {
            let mut mapping = json!({"frame_id":id,"parent_id":"main","loader_id":"pair-loader","session_id":"root","url":"https://pair.example/embedded","web_navigation_frame_id":web_id});
            if state.ambiguous_frames {
                mapping["unreadable_reason"] = json!("ambiguous");
                mapping
                    .as_object_mut()
                    .unwrap()
                    .remove("web_navigation_frame_id");
            }
            mappings.push(mapping);
        }
    }
    if state.stray_navigation {
        mappings.push(json!({"frame_id":"stray","parent_id":"main","loader_id":"stray-loader","session_id":"root","url":"about:blank","unreadable_reason":"stale"}));
    }
    if state.stale_root_mapping {
        mappings[0]["unreadable_reason"] = json!("stale");
        mappings[0]
            .as_object_mut()
            .unwrap()
            .remove("web_navigation_frame_id");
    }
    Ok((
        json!({"tab":handle,"results":results,"interaction_epoch":tab.interaction,"connection_epoch":epoch,"popup_activated_briefly":state.popup || metadata_popup,"frame_mappings":mappings}),
        input,
    ))
}

fn ax() -> Value {
    json!({"nodes":[
        {"nodeId":"root","ignored":false,"role":{"value":"RootWebArea"},"name":{"value":"Page"},"backendDOMNodeId":1,"frameId":"main","childIds":["button","text","secret","foreign"]},
        {"nodeId":"button","ignored":false,"role":{"value":"button"},"name":{"value":"Go"},"backendDOMNodeId":3},
        {"nodeId":"text","ignored":false,"role":{"value":"textbox"},"name":{"value":"Message"},"backendDOMNodeId":4},
        {"nodeId":"secret","ignored":false,"role":{"value":"textbox"},"name":{"value":"Password"},"value":{"value":"secret-value"},"backendDOMNodeId":5},
        {"nodeId":"foreign","ignored":false,"role":{"value":"Iframe"},"name":{"value":"Embedded page"},"backendDOMNodeId":6}
    ]})
}

fn dom(new_tab: bool, password: bool, payment: bool, untyped_button: bool) -> Value {
    let button_attributes = if new_tab {
        json!(["href", "/new", "target", "_blank"])
    } else if untyped_button {
        json!([])
    } else {
        json!(["type", "button"])
    };
    json!({"nodes":[
        {"nodeId":1,"backendNodeId":1,"nodeType":9,"nodeName":"#document","localName":"","nodeValue":""},
        {"nodeId":2,"parentId":1,"backendNodeId":2,"nodeType":1,"nodeName":"DIV","localName":"div","attributes":[]},
        {"nodeId":3,"parentId":2,"backendNodeId":3,"nodeType":1,"nodeName":if new_tab {"A"} else {"BUTTON"},"localName":if new_tab {"a"} else {"button"},"attributes":button_attributes},
        {"nodeId":4,"parentId":2,"backendNodeId":4,"nodeType":1,"nodeName":"INPUT","localName":"input","attributes":if payment { json!(["type","text","autocomplete","cc-number"]) } else { json!(["type",if password {"password"} else {"text"}]) }},
        {"nodeId":5,"parentId":2,"backendNodeId":5,"nodeType":1,"nodeName":"INPUT","localName":"input","attributes":["type","password"]},
        {"nodeId":6,"parentId":2,"backendNodeId":6,"nodeType":1,"nodeName":"IFRAME","localName":"iframe","attributes":[]}
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
async fn cdp_errors_name_the_failing_method_with_chromes_code_and_message() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_origin_always").await;
    let reference = reference(&snapshot, "Go");
    fixture.state.lock().unwrap().fail_method = Some((
        "DOM.getContentQuads",
        -32000,
        "Could not compute content quads.".into(),
    ));
    let (reply, _) = fixture
        .call(1, click(&tab, &snapshot, &reference), "allow_30m")
        .await;
    assert_eq!(reply["reason"], "cdp_error", "{reply}");
    assert_eq!(
        reply["detail"],
        json!({"method":"DOM.getContentQuads","code":-32000,"message":"Could not compute content quads."})
    );
    assert_eq!(reply["input_dispatched"], false);
    assert!(fixture.state.lock().unwrap().inputs.is_empty());

    // Anything that does not look like a fixed protocol string is replaced.
    for message in ["line one\nline two".to_owned(), "x".repeat(201)] {
        fixture.state.lock().unwrap().fail_method = Some(("DOM.getContentQuads", -32000, message));
        let (reply, _) = fixture
            .call(1, click(&tab, &snapshot, &reference), "allow_30m")
            .await;
        assert_eq!(
            reply["detail"],
            json!({"method":"DOM.getContentQuads","code":-32000,"message":"Chrome debugger command failed"}),
            "{reply}"
        );
    }
}

#[tokio::test]
async fn input_plans_enable_the_dom_agent_before_each_flattened_document_read() {
    // The extension detaches between plans, so an agent enabled by one plan is
    // gone in the next. A plan that reads the flattened DOM without enabling
    // it first is refused by Chrome before any input is sent.
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_origin_always").await;
    let (clicked, _) = fixture
        .call(
            1,
            click(&tab, &snapshot, &reference(&snapshot, "Go")),
            "allow_30m",
        )
        .await;
    assert_eq!(clicked["outcome"], "ok", "{clicked}");
    let state = fixture.state.lock().unwrap();
    assert_eq!(
        state.inputs,
        ["Input.dispatchMouseEvent", "Input.dispatchMouseEvent"]
    );
    let mut reads = 0;
    for plan in &state.commands {
        let methods: Vec<&str> = plan["commands"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|command| command["method"].as_str().unwrap())
            .collect();
        if let Some(read) = methods
            .iter()
            .position(|method| *method == "DOM.getFlattenedDocument")
        {
            reads += 1;
            assert!(methods[..read].contains(&"DOM.enable"), "{methods:?}");
        }
    }
    // Five flattened-DOM reads: both frame captures, click classification, and
    // target-state plus hit-test verification immediately before the mouse pair.
    assert_eq!(reads, 5);
}

#[tokio::test]
async fn a_form_less_untyped_button_click_asks_once_at_its_declared_level() {
    // A <button> defaults to type submit, but with no form owner it submits
    // nothing. It must classify at the declared level, so the read card is the
    // only card: one invocation, one allow_30m ask.
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    fixture.state.lock().unwrap().untyped_button = true;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_30m").await;
    let (clicked, cards) = fixture
        .call(
            1,
            click(&tab, &snapshot, &reference(&snapshot, "Go")),
            "allow_30m",
        )
        .await;
    assert_eq!(clicked["outcome"], "ok", "{clicked}");
    assert_eq!(cards.len(), 1, "{cards:?}");
    assert_eq!(cards[0]["scope"]["severity_tier"], 2);
}

#[tokio::test]
async fn per_site_ask_is_required_and_thirty_minute_approval_is_reused() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    for number in 0..2 {
        let (reply, cards) = fixture.snapshot(1, &tab, "allow_30m").await;
        assert_eq!(reply["outcome"], "ok", "{reply}");
        assert_eq!(
            cards.len(),
            usize::from(number == 0),
            "the site row should authorize the second read"
        );
        if let Some(card) = cards.first() {
            assert!(card["prompt"]
                .as_str()
                .unwrap()
                .contains("your own Chrome, signed in as you"));
            assert!(card["options"]
                .as_array()
                .unwrap()
                .iter()
                .any(|option| option["id"] == "allow_30m"));
        }
        assert!(!reply["state_text"]
            .as_str()
            .unwrap()
            .contains("secret-value"));
        assert!(reply["state_text"]
            .as_str()
            .unwrap()
            .contains("Child message"));
    }
    assert_eq!(
        fixture.state.lock().unwrap().captures,
        vec!["main", "foreign", "main", "foreign"]
    );
}

#[tokio::test]
async fn open_navigate_snapshot_never_launches_an_owned_browser() {
    let fixture = Fixture::new();
    let (opened, _) = fixture
        .call(
            1,
            json!({"browser":"user","action":"open_tab"}),
            "allow_30m",
        )
        .await;
    assert_eq!(opened["outcome"], "ok", "{opened}");
    let tab = opened["tab"].as_str().unwrap();
    let (navigated, cards) = fixture.call(1, json!({"browser":"user","action":"navigate","tab":tab,"url":"https://example.com/","intent":"read","wait":"settle","severity":{"tier":1,"credential":false,"financial":false}}), "allow_30m").await;
    assert_eq!(navigated["outcome"], "ok", "{navigated}");
    assert_eq!(navigated["settled"], false);
    assert!(navigated["remedy"]
        .as_str()
        .unwrap()
        .contains("Read the page before acting"));
    assert_eq!(cards.len(), 1);
    let (snapshot, cards) = fixture.snapshot(1, tab, "allow_30m").await;
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    assert!(cards.is_empty());
    assert!(!fixture
        .state
        .lock()
        .unwrap()
        .commands
        .iter()
        .any(|command| command["action"] == "launch"));
}

#[tokio::test]
async fn cold_snapshots_after_unsettled_navigation_refuse_empty_or_missing_ax_children() {
    let mut root = ax()["nodes"][0].clone();
    root["childIds"] = json!(["not_returned"]);
    for capture in [json!({"nodes":[]}), json!({"nodes":[root]})] {
        let fixture = Fixture::new();
        let tab = fixture.claim(1).await;
        fixture.state.lock().unwrap().top_level_only = true;
        let (navigated, cards) = fixture.call(1, json!({"browser":"user","action":"navigate","tab":tab,"url":"https://example.com/cold","wait":"settle","intent":"load page","severity":{"tier":1,"credential":false,"financial":false}}), "allow_30m").await;
        assert_eq!(navigated["outcome"], "ok", "{navigated}");
        assert_eq!(navigated["settled"], false);
        assert_eq!(cards.len(), 1);
        fixture.state.lock().unwrap().ax_override = Some(capture);
        let (snapshot, cards) = fixture.snapshot(1, &tab, "allow_30m").await;
        assert!(cards.is_empty());
        assert_eq!(snapshot["reason"], "snapshot_not_ready", "{snapshot}");
        assert_eq!(snapshot["remedy"], "read again");
        assert!(snapshot.get("state_text").is_none());
        assert!(snapshot.get("snapshot_id").is_none());
        assert!(fixture.state.lock().unwrap().inputs.is_empty());
    }
}

#[tokio::test]
async fn root_only_snapshots_disclose_unknown_readiness_without_rejecting_empty_pages() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let mut root = ax()["nodes"][0].clone();
    root["childIds"] = json!([]);
    {
        let mut state = fixture.state.lock().unwrap();
        state.top_level_only = true;
        state.ax_override = Some(json!({"nodes":[root]}));
    }
    let (snapshot, cards) = fixture.snapshot(1, &tab, "allow_30m").await;
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    assert_eq!(cards.len(), 1);
    assert_eq!(snapshot["settled"], false);
    assert_eq!(snapshot["truncated"], false);
    assert_eq!(snapshot["refs_truncated"], false);
    assert!(snapshot["settlement_reason"]
        .as_str()
        .unwrap()
        .contains("not observed"));
    assert!(snapshot["remedy"]
        .as_str()
        .unwrap()
        .contains("empty or still-loading"));
    assert!(crate::browser::validate_user_browser_result("snapshot", &snapshot).is_ok());
    fixture.state.lock().unwrap().ax_override = None;
    let (complete, cards) = fixture.snapshot(1, &tab, "allow_30m").await;
    assert_eq!(complete["outcome"], "ok", "{complete}");
    assert!(cards.is_empty());
    assert_eq!(complete["truncated"], false);
    assert_eq!(complete["refs_truncated"], false);
    assert!(complete["state_text"].as_str().unwrap().contains("Go"));
    assert!(complete.get("remedy").is_none());
}

#[tokio::test]
async fn bounded_ax_snapshots_preserve_projection_truncation_flags() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let mut capture = ax();
    capture["nodes"][1]["name"]["value"] = json!("X".repeat(8192));
    {
        let mut state = fixture.state.lock().unwrap();
        state.top_level_only = true;
        state.ax_override = Some(capture);
    }
    let (snapshot, cards) = fixture.snapshot(1, &tab, "allow_30m").await;
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    assert_eq!(cards.len(), 1);
    assert_eq!(snapshot["truncated"], true);
    assert_eq!(snapshot["refs_truncated"], true);
    assert!(snapshot["remedy"].as_str().unwrap().contains("partial"));
    assert!(crate::browser::validate_user_browser_result("snapshot", &snapshot).is_ok());
}

#[tokio::test]
async fn snapshot_byte_budget_is_disclosed_as_partial() {
    let mut root = ax()["nodes"][0].clone();
    root["childIds"] = json!([]);
    for (top_level_only, max_bytes, capture) in [
        (true, 64, None),
        (false, 64, None),
        (true, 1, Some(json!({"nodes":[root]}))),
    ] {
        let fixture = Fixture::new();
        let tab = fixture.claim(1).await;
        {
            let mut state = fixture.state.lock().unwrap();
            state.top_level_only = top_level_only;
            state.ax_override = capture;
        }
        let (snapshot, cards) = fixture
            .call(
                1,
                json!({"browser":"user","action":"snapshot","tab":tab,"max_bytes":max_bytes}),
                "allow_30m",
            )
            .await;
        assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
        assert_eq!(cards.len(), 1);
        assert_eq!(snapshot["truncated"], true);
        assert_eq!(snapshot["refs_truncated"], false);
        assert!(snapshot["state_text"].as_str().unwrap().len() <= max_bytes);
        assert!(snapshot["remedy"].as_str().unwrap().contains("partial"));
        assert!(crate::browser::validate_user_browser_result("snapshot", &snapshot).is_ok());
    }
}

#[tokio::test]
async fn outside_group_tab_is_refused_before_any_cdp_command() {
    let fixture = Fixture::new();
    let (status, _) = fixture
        .call(1, json!({"browser":"user","action":"status"}), "allow_30m")
        .await;
    assert_eq!(status["tabs"].as_array().unwrap().len(), 1);
    assert_eq!(status["tabs"][0]["tab"], "handed");
    let before = fixture.state.lock().unwrap().commands.len();
    let (reply, cards) = fixture.snapshot(1, "outside", "allow_30m").await;
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
    let (unclaimed, _) = fixture.snapshot(1, "handed", "allow_30m").await;
    assert_eq!(unclaimed["reason"], "tab_not_claimed_by_route");
    let tab = fixture.claim(1).await;
    let (held, _) = fixture
        .call(
            2,
            json!({"browser":"user","action":"claim_tab","tab":tab}),
            "allow_30m",
        )
        .await;
    assert_eq!(held["reason"], "tab_already_claimed");
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_30m").await;
    let reference = reference(&snapshot, "Go");
    let (other, _) = fixture
        .call(
            2,
            json!({"browser":"user","action":"open_tab"}),
            "allow_30m",
        )
        .await;
    let other_tab = other["tab"].as_str().unwrap();
    let (reused, _) = fixture
        .call(2, click(other_tab, &snapshot, &reference), "allow_30m")
        .await;
    assert_eq!(reused["reason"], "snapshot_scope_mismatch");
    let mut own_ref = click(&tab, &snapshot, "own-ref");
    own_ref["snapshot_id"] = json!("own-snapshot");
    let (refused, _) = fixture.call(1, own_ref, "allow_30m").await;
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
    let (reply, cards) = fixture.call(1, json!({"browser":"user","action":"navigate","tab":tab,"url":"https://example.com/go","intent":"read","severity":{"tier":1,"credential":false,"financial":false},"read_page":true}), "allow_30m").await;
    assert_eq!(reply["reason"], "landing_site_not_authorized");
    assert_eq!(cards.len(), 1);
    assert!(reply.get("read_page").is_none());
    assert!(reply.get("state_text").is_none());
    assert!(fixture.state.lock().unwrap().captures.is_empty());
}

#[tokio::test]
async fn human_input_before_click_and_between_typing_steps_stops_all_further_input() {
    for before in [true, false] {
        let fixture = Fixture::new();
        let tab = fixture.claim(1).await;
        let (snapshot, _) = fixture.snapshot(1, &tab, "allow_origin_always").await;
        let args = if before {
            click(&tab, &snapshot, &reference(&snapshot, "Go"))
        } else {
            json!({"browser":"user","action":"type","tab":tab,"ref":reference(&snapshot, "Message"),"text":"not dispatched"})
        };
        {
            let mut state = fixture.state.lock().unwrap();
            state.human_before_input = before;
            state.human_after_input = !before;
        }
        let (reply, _) = fixture.call(1, args, "allow_30m").await;
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
            .call(1, click(&tab, &fresh, fresh_reference), "allow_30m")
            .await;
        assert_eq!(success["outcome"], "ok", "{success}");
    }
}

#[tokio::test]
async fn detached_human_input_and_reconnect_never_refresh_a_refused_baseline() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_30m").await;
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
            .call(1, click(&tab, &snapshot, &reference), "allow_30m")
            .await;
        assert_eq!(reply["reason"], "state_changed_by_person");
    }
    assert!(fixture.state.lock().unwrap().inputs.is_empty());
    fixture
        .planes
        .user_browser
        .disconnect_for_policy_test(fixture.epoch);
    let (reply, _) = fixture
        .call(1, click(&tab, &snapshot, &reference), "allow_30m")
        .await;
    assert_eq!(reply["reason"], "not_connected");
    assert_eq!(reply["browser"], "user");
}

#[tokio::test]
async fn close_and_goodbye_release_without_closing_any_person_tab() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let (reply, _) = fixture
        .call(1, json!({"browser":"user","action":"close"}), "allow_30m")
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
            "allow_30m",
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
async fn background_clicks_keep_focus_press_and_release_in_one_attachment() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_30m").await;
    let (image, _) = fixture
        .call(
            1,
            json!({"browser":"user","action":"screenshot","tab":tab}),
            "allow_30m",
        )
        .await;
    let point = json!({"browser":"user","action":"click_point","tab":tab,"snapshot_id":image["snapshot_id"],"point":{"x":0,"y":0},"image_width_px":1,"image_height_px":1,"intent":"click","severity":{"tier":2,"credential":false,"financial":false}});
    for args in [click(&tab, &snapshot, &reference(&snapshot, "Go")), point] {
        let before = fixture.state.lock().unwrap().commands.len();
        let (clicked, _) = fixture.call(1, args, "allow_30m").await;
        assert_eq!(clicked["outcome"], "ok", "{clicked}");
        let state = fixture.state.lock().unwrap();
        let mut pairs = 0;
        for plan in &state.commands[before..] {
            let commands = plan["commands"].as_array().unwrap();
            if let Some(index) = commands
                .iter()
                .position(|command| command["method"] == "Input.dispatchMouseEvent")
            {
                // One attachment owns the complete gesture, including any
                // release-only cleanup needed after a between-event refusal.
                assert_eq!(index, 1, "mouse input lacks focus emulation: {plan}");
                assert_eq!(commands.len(), 3, "{plan}");
                assert_eq!(
                    commands[index - 1]["method"],
                    "Emulation.setFocusEmulationEnabled"
                );
                assert_eq!(commands[index - 1]["params"], json!({"enabled":true}));
                assert_eq!(commands[index - 1]["frame_id"], "main");
                assert_eq!(commands[index - 1]["session_id"], "root");
                assert_eq!(commands[index]["params"]["type"], "mousePressed");
                let mut released = commands[index].clone();
                released["params"]["type"] = json!("mouseReleased");
                assert_eq!(commands[index + 1], released, "{plan}");
                pairs += 1;
            }
        }
        assert_eq!(pairs, 1);
    }
}

#[tokio::test]
async fn credential_payment_typing_refuses_and_normal_typing_uses_background_focus() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_30m").await;
    let password = reference(&snapshot, "Password");
    let (refused, _) = fixture.call(1, json!({"browser":"user","action":"type","tab":tab,"ref":password,"text":"do not persist this"}), "allow_30m").await;
    assert_eq!(
        refused["reason"], "credential_payment_or_ineligible_field",
        "{refused}"
    );
    assert!(fixture.state.lock().unwrap().inputs.is_empty());
    let text = reference(&snapshot, "Message");
    let (typed, _) = fixture.call(1, json!({"browser":"user","action":"type","tab":tab,"ref":text,"text":"do not persist this","clear_first":true}), "allow_30m").await;
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
            "allow_30m",
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
            "allow_30m",
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
    let (reply, cards) = fixture.snapshot(1, &tab, "allow_30m").await;
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
            "allow_30m",
        )
        .await;
    assert_eq!(image["outcome"], "ok", "{image}");
    assert_eq!(image["image_width_px"], 1);
    let point = json!({"browser":"user","action":"click_point","tab":tab,"snapshot_id":image["snapshot_id"],"point":{"x":0,"y":0},"image_width_px":1,"image_height_px":1,"intent":"click","severity":{"tier":2,"credential":false,"financial":false}});
    let (clicked, _) = fixture.call(1, point.clone(), "allow_30m").await;
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
    let (foreign, cards) = fixture.call(1, point.clone(), "allow_30m").await;
    assert_eq!(cards.len(), 1);
    assert_eq!(foreign["outcome"], "ok", "{foreign}");
    assert_eq!(foreign["input_dispatched"], true);
    fixture.state.lock().unwrap().inputs.clear();
    fixture.state.lock().unwrap().viewport_changed = true;
    let (changed, _) = fixture.call(1, point, "allow_30m").await;
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
            "allow_30m",
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
async fn scroll_on_user_browser_is_typed_unsupported_without_extension_commands() {
    let fixture = Fixture::new();
    let (reply, _) = fixture
        .call(
            1,
            json!({"browser":"user","action":"scroll","direction":"down"}),
            "deny",
        )
        .await;
    assert_eq!(reply["outcome"], "refused", "{reply}");
    assert_eq!(reply["reason"], "unsupported_on_user_browser", "{reply}");
    assert!(fixture.state.lock().unwrap().commands.is_empty());
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
    let (reply, _) = fixture.call(1, json!({"browser":"user","action":"type","tab":tab,"ref":reference(&snapshot,"Message"),"text":"4111"}), "allow_30m").await;
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
    let authorized = json!({"browser":"user","outcome":"ok","origin":"https://example.test","input_dispatched":false});
    assert!(crate::browser::validate_user_browser_result("open_grant", &authorized).is_ok());
    let mut unknown_origin = authorized.clone();
    unknown_origin["unexpected"] = json!(true);
    assert!(crate::browser::validate_user_browser_result("open_grant", &unknown_origin).is_err());

    let mut partial = valid.clone();
    partial["truncated"] = json!(true);
    partial["refs_truncated"] = json!(false);
    assert!(crate::browser::validate_user_browser_result("snapshot", &partial).is_ok());
    partial["truncated"] = json!("true");
    assert!(crate::browser::validate_user_browser_result("snapshot", &partial).is_err());
    let mut invalid = valid.clone();
    invalid["undeclared"] = json!(true);
    assert!(crate::browser::validate_user_browser_result("snapshot", &invalid).is_err());
    let mut untagged = valid;
    untagged.as_object_mut().unwrap().remove("browser");
    assert!(crate::browser::validate_user_browser_result("snapshot", &untagged).is_err());
    let cdp_error = json!({"browser":"user","outcome":"refused","reason":"cdp_error","input_dispatched":false,
        "detail":{"method":"DOM.getContentQuads","code":-32000,"message":"Could not compute content quads."}});
    assert!(crate::browser::validate_user_browser_result("click", &cdp_error).is_ok());
    let mut with_data = cdp_error;
    with_data["detail"]["data"] = json!("page text");
    assert!(crate::browser::validate_user_browser_result("click", &with_data).is_err());
}

#[tokio::test]
async fn user_browser_typing_never_sends_text_key_events() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_30m").await;
    let (reply, _) = fixture.call(1, json!({"browser":"user","action":"type","tab":tab,"ref":reference(&snapshot,"Message"),"text":"hello","clear_first":true}), "allow_30m").await;
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
            "allow_30m",
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
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_30m").await;
    let (reply, _) = fixture.call(1, json!({"browser":"user","action":"type","tab":tab,"ref":reference(&snapshot,"Message"),"text":"hello","clear_first":true}), "allow_30m").await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    let state = fixture.state.lock().unwrap();
    let mut functions = 0;
    for plan in &state.commands {
        let Some(commands) = plan["commands"].as_array() else {
            continue;
        };
        for (index, command) in commands.iter().enumerate() {
            if !command["frame_id"].is_null() {
                assert!(
                    command["frame_id"].is_string(),
                    "routing uses verified CDP frame ids"
                );
                assert!(command["loader_id"].is_string());
                assert!(command["session_id"].is_string());
            }
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
async fn embedded_frame_fields_are_read_under_the_top_page_grant_and_zoomable() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_30m").await;
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    assert!(snapshot["omitted_frames"].is_null());
    assert!(snapshot["state_text"]
        .as_str()
        .unwrap()
        .contains("Child message"));
    assert!(snapshot["state_text"]
        .as_str()
        .unwrap()
        .contains("child field value"));
    let child = reference(&snapshot, "Child message");
    let (zoom, cards) = fixture
        .call(
            1,
            json!({"browser":"user","action":"snapshot","tab":tab,"zoom":child}),
            "allow_30m",
        )
        .await;
    assert_eq!(zoom["outcome"], "ok", "{zoom}");
    assert!(cards.is_empty());
    assert!(zoom["state_text"]
        .as_str()
        .unwrap()
        .contains("Child message"));
    let owner = reference(&snapshot, "Embedded page");
    let (owner_zoom, _) = fixture
        .call(
            1,
            json!({"browser":"user","action":"snapshot","tab":tab,"zoom":owner}),
            "allow_30m",
        )
        .await;
    assert_eq!(owner_zoom["outcome"], "ok", "{owner_zoom}");
    assert!(owner_zoom["state_text"]
        .as_str()
        .unwrap()
        .contains("Child message"));
    assert!(!snapshot["state_text"].as_str().unwrap().contains("FOREIGN"));
    let state = fixture.planes.user_browser.target().state();
    let retained = state
        .snapshots
        .get(snapshot["snapshot_id"].as_str().unwrap())
        .unwrap();
    assert!(!retained.refs.is_empty());
    assert!(retained
        .refs
        .values()
        .any(
            |reference| reference.frame.parent_id.as_deref() == Some("main")
                && reference.frame.frame_id == "foreign"
                && reference.frame.session_id == "child-target"
        ));
}

#[tokio::test]
async fn authority_changing_severity_is_never_grantable_in_the_user_browser() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_30m").await;
    let mut request = click(&tab, &snapshot, &reference(&snapshot, "Go"));
    request["severity"]["tier"] = json!(5);
    let (reply, cards) = fixture.call(1, request, "allow_30m").await;
    assert_eq!(reply["reason"], "severity_ungrantable");
    assert!(cards.is_empty());
    assert!(fixture.state.lock().unwrap().inputs.is_empty());
}

// --- the site card through Cingulate ----------------------------------------

/// Wait until `check` holds, for a test that acts while a call is held.
async fn until(mut check: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !check() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the call reached the awaited step");
}

fn snapshot_args(tab: &str) -> Value {
    json!({"browser":"user","action":"snapshot","tab":tab})
}

fn this_session() -> crate::cingulate_client::live_call::SessionKey {
    crate::computer_grants::tests::session_key("test-project")
}

/// The bounded wait is not the card deadline. Detach the pending card so a
/// late answer wakes the agent, without reading or dispatching in the meantime.
#[tokio::test]
async fn an_unanswered_site_card_detaches_and_replies_pending_without_content() {
    let script = ScriptedCingulate::new();
    let fixture = Fixture::scripted(&script);
    let tab = fixture.claim(1).await;
    script
        .then(
            wire::CONSENT_REQUEST,
            Reply::Result(json!({"elicitation_id":"el_site_silent"})),
        )
        .then(
            wire::CONSENT_AWAIT,
            Reply::Result(json!({"elicitation_id":"el_site_silent","state":"pending"})),
        )
        .then(
            wire::CONSENT_DETACH,
            Reply::Result(
                json!({"elicitation_id":"el_site_silent","state":"pending","detached":true}),
            ),
        );
    let reply = fixture
        .finish(fixture.start(1, snapshot_args(&tab), ""))
        .await;
    assert_eq!(reply["outcome"], "consent_pending", "{reply}");
    assert_eq!(reply["ask_id"], "el_site_silent", "{reply}");
    assert!(reply.get("state_text").is_none());
    assert_eq!(
        script.methods(),
        [
            wire::CONSENT_REQUEST,
            wire::CONSENT_AWAIT,
            wire::CONSENT_DETACH
        ]
    );
    assert_eq!(script.calls()[1].1["timeout_ms"], 120_000);
    assert!(fixture.planes.consent.raised("el_site_silent").is_some());
    assert_eq!(fixture.planes.consent.unapplied(&this_session()).len(), 1);
    assert!(fixture.state.lock().unwrap().captures.is_empty());
}

/// A cancel, the call's route closing, and the module draining each end the
/// held call with its own word, withdraw the card rather than detach it, and
/// leave nothing in the registry.
#[tokio::test]
async fn cancel_route_close_and_drain_withdraw_a_held_site_card() {
    for (event, reason) in [
        ("cancel", Some("cancelled")),
        // A closed route gets no reply at all.
        ("route_close", None),
        ("drain", Some("module_draining")),
    ] {
        let script = ScriptedCingulate::new();
        let fixture = Fixture::scripted(&script);
        let tab = fixture.claim(1).await;
        script
            .then(
                wire::CONSENT_REQUEST,
                Reply::Result(json!({"elicitation_id":"el_site_held"})),
            )
            .then(wire::CONSENT_AWAIT, Reply::Hang)
            .then(
                wire::CONSENT_WITHDRAW,
                Reply::Result(json!({"elicitation_id":"el_site_held","state":"withdrawn"})),
            );
        let started = fixture.start(1, snapshot_args(&tab), "");
        until(|| script.methods().len() == 2).await;
        match event {
            "cancel" => fixture
                .planes
                .cancellations
                .get((1, 1, started.corr))
                .unwrap()
                .cancel(),
            "route_close" => {
                fixture.planes.routes.remove(1, 1);
            }
            _ => {
                fixture.planes.drain_signal.send_replace(true);
            }
        }
        match reason {
            Some(reason) => {
                let reply = fixture.finish(started).await;
                if event == "cancel" {
                    assert_eq!(
                        reply,
                        json!({"browser":"user", "outcome":"cancelled", "input_dispatched":false})
                    );
                } else {
                    assert_eq!(reply["reason"], reason, "{event}: {reply}");
                }
            }
            None => {
                let mut started = started;
                tokio::time::timeout(Duration::from_secs(5), &mut started.task)
                    .await
                    .expect("the call ends when its route closes")
                    .unwrap();
                assert!(
                    started.replies.try_recv().is_err(),
                    "{event}: a reply was sent"
                );
            }
        }
        assert_eq!(
            script.methods(),
            [
                wire::CONSENT_REQUEST,
                wire::CONSENT_AWAIT,
                wire::CONSENT_WITHDRAW
            ],
            "{event}"
        );
        assert!(fixture.planes.consent.raised("el_site_held").is_none());
        assert!(fixture.state.lock().unwrap().captures.is_empty());
    }
}

#[tokio::test]
async fn turn_stop_cancel_user_browser_site_card_has_no_retry_advice() {
    let script = ScriptedCingulate::new();
    let fixture = Fixture::scripted(&script);
    let tab = fixture.claim(1).await;
    script
        .then(
            wire::CONSENT_REQUEST,
            Reply::Result(json!({"elicitation_id":"el_site_stop"})),
        )
        .then(wire::CONSENT_AWAIT, Reply::Hang)
        .then(
            wire::CONSENT_WITHDRAW,
            Reply::Result(json!({"elicitation_id":"el_site_stop","state":"withdrawn"})),
        );
    let request = tool_frame(1, 807, snapshot_args(&tab));
    let (writer, mut replies) = mpsc::channel(8);
    crate::handle_frame_for_test(request.clone(), &writer, &fixture.planes)
        .await
        .unwrap();
    until(|| script.methods().len() == 2).await;
    let cancel = crate::turn_stop_vectors::cancel(&request);
    crate::handle_frame_for_test(cancel.clone(), &writer, &fixture.planes)
        .await
        .unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(2), replies.recv())
        .await
        .expect("cancelled user-browser card answers promptly")
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&reply.body).unwrap(),
        json!({
            "browser":"user", "outcome":"cancelled", "input_dispatched":false,
        })
    );
    assert_eq!(
        script.methods(),
        [
            wire::CONSENT_REQUEST,
            wire::CONSENT_AWAIT,
            wire::CONSENT_WITHDRAW
        ]
    );
    assert!(fixture.planes.consent.raised("el_site_stop").is_none());
    assert!(fixture.state.lock().unwrap().captures.is_empty());
    crate::turn_stop_vectors::check(
        "user-browser-site-card",
        "parked awaiting a user-browser site card; card is withdrawn on Cancel",
        &request,
        &cancel,
        Some(&reply),
    );
}

/// "Always on this site" stores a standing row whose consent reference is the
/// card's Cingulate id, and the answer is marked applied so no later call of
/// the session reads it again.
#[tokio::test]
async fn an_always_answer_records_the_cingulate_card_id_and_is_applied() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let (reply, cards) = fixture.snapshot(1, &tab, "allow_origin_always").await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(cards.len(), 1);
    let rows = fixture
        .planes
        .management
        .agent_grants()
        .live_rows(
            Some("test-project"),
            fixture.planes.management.agent_grants().now_ms(),
        )
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].card_ref.as_deref(), Some("el_site_1"));
    assert_eq!(rows[0].expires_at_ms, None);
    assert!(fixture.planes.consent.raised("el_site_1").unwrap().applied);
    assert!(fixture.planes.consent.unapplied(&this_session()).is_empty());
}

/// A choice the card did not offer is not a refusal: no decision can be read
/// from it, so the reply says `unrecognized_answer` and nothing is exposed.
#[tokio::test]
async fn a_choice_the_card_did_not_offer_is_unrecognized_never_declined() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let (reply, cards) = fixture.snapshot(1, &tab, "approve_everything").await;
    assert_eq!(cards.len(), 1);
    assert_eq!(reply["reason"], "unrecognized_answer", "{reply}");
    assert!(reply.get("state_text").is_none());
    assert!(fixture.state.lock().unwrap().captures.is_empty());
}

/// A call from no agent session raises no card and opens no route to
/// Cingulate; the reply says where the call must come from.
#[tokio::test]
async fn a_call_without_an_agent_session_raises_no_site_card() {
    let script = ScriptedCingulate::new();
    let fixture = Fixture::scripted(&script);
    let tab = fixture.claim(1).await;
    let facts = fixture.planes.routes.get(1, 1).unwrap();
    fixture.planes.routes.insert(1, 1, facts.with_scope(None));
    let reply = fixture
        .finish(fixture.start(1, snapshot_args(&tab), ""))
        .await;
    assert_eq!(reply["reason"], "consent_unavailable", "{reply}");
    // The reply schema admits the reason, so the reply is not replaced by a
    // `result_schema_violation` refusal on its way out.
    assert_eq!(reply["detail"]["reason"], "no_agent_session", "{reply}");
    assert_eq!(
        reply["remedy"],
        "call from the agent session that needs the permission; it can raise the card"
    );
    assert_eq!(script.opens(), 0);
    assert!(fixture.state.lock().unwrap().captures.is_empty());
}

/// The session drain leaves a site card alone while a call is holding it,
/// and withdraws one that no call holds (such as a card left in the registry
/// by a restart). Otherwise that card would stay on the person's phone, and
/// as an unapplied registry entry it would make every later call of the
/// session open a route to Cingulate to look for its answer.
#[tokio::test]
async fn the_drain_leaves_a_held_site_card_and_withdraws_an_abandoned_one() {
    use crate::cingulate_client::desk::RegistryStore;
    let dir = std::env::temp_dir().join(format!(
        "user-browser-drain-{}-{}",
        std::process::id(),
        line!()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let store = Arc::new(FileRegistryStore::new(dir.join("registry.json")));
    let card = RaisedCard {
        elicitation_id: "el_site_abandoned".into(),
        session: this_session(),
        kind: CardKind::UserBrowserSite,
        subject: subject::user_browser_site("https://example.com"),
        grant_ids: vec!["allow_30m".into()],
        decline_id: SITE_DENY.into(),
        next_steps: Default::default(),
        applied: false,
        lifecycle: Default::default(),
    };
    store.save(std::slice::from_ref(&card)).unwrap();
    let script = ScriptedCingulate::new();
    let planes = Planes::with_cingulate_for_test(
        Arc::new(cerebellum_core::health::HealthState::new()),
        None,
        Arc::new(script.clone()),
        store.clone(),
    );
    crate::install_browser_test_bind(&planes.routes, 1, 1, &[]);
    let facts = planes.routes.get(1, 1).unwrap();
    planes.routes.insert(
        1,
        1,
        facts.with_scope(Some(crate::computer_grants::tests::stamp("test-project"))),
    );

    script
        .then(
            wire::CONSENT_ANSWERS,
            Reply::Result(json!({"records":[],"cursor":1})),
        )
        .then(wire::CONSENT_ACK, Reply::Result(json!({"cursor":1})));
    {
        let _held = SiteCardHold::enter(&planes.user_browser_cards, &card.subject);
        crate::computer_grants::tests::drain_call(&planes, 1, 1).await;
    }
    assert_eq!(
        script.methods(),
        [wire::CONSENT_ANSWERS, wire::CONSENT_ACK],
        "a held card was read or withdrawn"
    );
    assert!(planes.consent.raised("el_site_abandoned").is_some());

    script
        .then(
            wire::CONSENT_GET,
            Reply::Result(json!({"elicitation_id":"el_site_abandoned","state":"pending"})),
        )
        .then(
            wire::CONSENT_WITHDRAW,
            Reply::Result(json!({"elicitation_id":"el_site_abandoned","state":"withdrawn"})),
        )
        .then(
            wire::CONSENT_ANSWERS,
            Reply::Result(json!({"records":[],"cursor":1})),
        )
        .then(wire::CONSENT_ACK, Reply::Result(json!({"cursor":1})));
    crate::computer_grants::tests::drain_call(&planes, 1, 1).await;
    assert_eq!(
        script.methods()[2..],
        [
            wire::CONSENT_GET,
            wire::CONSENT_WITHDRAW,
            wire::CONSENT_ANSWERS,
            wire::CONSENT_ACK
        ]
    );
    assert!(planes.consent.raised("el_site_abandoned").is_none());
    assert!(store.load().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

mod permission_cards;
mod worker;

mod agent_enforcement;

#[tokio::test]
async fn same_origin_child_click_routes_to_the_verified_frame_without_a_new_card() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    fixture.state.lock().unwrap().same_origin_child = true;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_30m").await;
    let (top_clicked, top_cards) = fixture
        .call(
            1,
            click(&tab, &snapshot, &reference(&snapshot, "Go")),
            "allow_30m",
        )
        .await;
    assert_eq!(top_clicked["outcome"], "ok");
    assert_eq!(top_cards.len(), 1);
    let (reply, cards) = fixture
        .call(
            1,
            click(&tab, &snapshot, &reference(&snapshot, "Child go")),
            "allow_30m",
        )
        .await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert!(cards.is_empty());
    let state = fixture.state.lock().unwrap();
    let sent: Vec<_> = state
        .commands
        .iter()
        .flat_map(|plan| plan["commands"].as_array().into_iter().flatten())
        .filter(|command| {
            command["method"] == "Input.dispatchMouseEvent" && command["frame_id"] == "foreign"
        })
        .collect();
    assert_eq!(sent.len(), 2);
    assert!(sent.iter().all(|command| command["frame_id"] == "foreign"
        && command["session_id"] == "root"
        && command["loader_id"] == "foreign-loader"));
}

#[tokio::test]
async fn cross_origin_child_typing_requires_its_own_origin_card() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_30m").await;
    let (reply, cards) = fixture.call(1, json!({"browser":"user","action":"type","tab":tab,"ref":reference(&snapshot,"Child message"),"text":"hello"}), "deny").await;
    assert_eq!(
        cards.len(),
        1,
        "child input must not reuse the top-page grant"
    );
    assert!(cards[0].to_string().contains("https://ungranted.example"));
    assert_eq!(reply["reason"], "consent_declined", "{reply}");
    assert!(fixture.state.lock().unwrap().inputs.is_empty());
    let (reply, cards) = fixture.call(1, json!({"browser":"user","action":"type","tab":tab,"ref":reference(&snapshot,"Child message"),"text":"hello"}), "allow_30m").await;
    assert_eq!(cards.len(), 1);
    assert_eq!(reply["outcome"], "ok", "{reply}");
    let state = fixture.state.lock().unwrap();
    assert!(state
        .inputs
        .iter()
        .any(|method| method == "Input.insertText"));
    for command in state
        .commands
        .iter()
        .flat_map(|plan| plan["commands"].as_array().into_iter().flatten())
        .filter(|command| command["method"] == "Input.insertText")
    {
        assert_eq!(command["frame_id"], "foreign");
        assert_eq!(command["session_id"], "child-target");
    }
}

#[tokio::test]
async fn credential_field_in_a_child_is_refused_even_with_its_origin_granted() {
    for payment in [false, true] {
        let fixture = Fixture::new();
        let tab = fixture.claim(1).await;
        fixture.state.lock().unwrap().password = !payment;
        fixture.state.lock().unwrap().payment = payment;
        let (snapshot, _) = fixture.snapshot(1, &tab, "allow_30m").await;
        assert!(!snapshot["state_text"]
            .as_str()
            .unwrap()
            .contains("child field value"));
        let (reply, _) = fixture.call(1, json!({"browser":"user","action":"type","tab":tab,"ref":reference(&snapshot,"Child message"),"text":"secret"}), "allow_30m").await;
        assert_eq!(
            reply["reason"], "credential_payment_or_ineligible_field",
            "{reply}"
        );
        assert!(fixture.state.lock().unwrap().inputs.is_empty());
    }
}

// Keep the driver runnable between clock steps so filesystem workers finish
// without Tokio jumping straight to a far-away action deadline.
async fn clocked_reply(mut call: Started, max_seconds: u64) -> Value {
    for _ in 0..=max_seconds * 10 {
        for _ in 0..64 {
            if let Ok(frame) = call.replies.try_recv() {
                call.task.await.unwrap();
                assert!(call.replies.try_recv().is_err());
                return serde_json::from_slice(&frame.body).unwrap();
            }
            tokio::task::yield_now().await;
        }
        tokio::time::advance(Duration::from_millis(100)).await;
    }
    panic!("no terminal reply inside the declared allowance");
}

#[tokio::test]
async fn user_snapshot_maximum_plans_complete_inside_its_budget() {
    let f = Fixture::new();
    f.state.lock().unwrap().top_level_only = true;
    let tab = f.claim(1).await;
    f.snapshot(1, &tab, "allow_30m").await;
    {
        let mut state = f.state.lock().unwrap();
        state.plan_count = 0;
        state.plan_delay = Duration::from_secs(23);
    }
    tokio::time::pause();
    let start = tokio::time::Instant::now();
    let reply = clocked_reply(
        f.start_arbitrated(json!({
            "browser":"user","action":"snapshot","tab":tab,"mode":"dom_full"
        })),
        130,
    )
    .await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(f.state.lock().unwrap().plan_count, 5);
    assert!(start.elapsed() <= Duration::from_millis(crate::budgets::USER_SNAPSHOT.work_ms));
}

#[tokio::test]
async fn user_slow_type_and_hanging_last_plan_end_at_the_shared_action_deadline() {
    for hanging in [false, true] {
        let f = Fixture::new();
        let tab = f.claim(1).await;
        let (snapshot, _) = f.snapshot(1, &tab, "allow_30m").await;
        let args = json!({"browser":"user","action":"type","tab":tab,
            "ref":reference(&snapshot,"textbox"),"text":"hello"});
        {
            let mut state = f.state.lock().unwrap();
            state.plan_count = 0;
            state.plan_delay = Duration::from_secs(27);
            state.hang_plan = hanging.then_some(10);
        }
        tokio::time::pause();
        let start = tokio::time::Instant::now();
        let allowance = crate::budgets::USER_TYPE.work_ms;
        let reply = clocked_reply(f.start_arbitrated(args), allowance / 1000 + 6).await;
        assert_eq!(reply["outcome"], "dispatch_outcome_unknown", "{reply}");
        assert_eq!(
            reply["detail"]["reason"], "action_deadline_exceeded",
            "{reply}"
        );
        assert_eq!(reply["detail"]["dispatched"], true);
        assert_eq!(f.state.lock().unwrap().plan_count, 10);
        assert!(start.elapsed() >= Duration::from_millis(allowance));
        assert!(start.elapsed() <= Duration::from_millis(allowance + 100));
        tokio::time::resume();
    }
}

#[tokio::test]
async fn ambiguous_child_pair_keeps_top_level_and_normal_child_readable() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    {
        let mut state = fixture.state.lock().unwrap();
        state.frame_pair = true;
        state.ambiguous_frames = true;
        state.same_origin_child = true;
    }
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_30m").await;
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    assert_eq!(snapshot["truncated"], true);
    assert_eq!(snapshot["omitted_frames"], 2);
    let text = snapshot["state_text"].as_str().unwrap();
    assert!(text.contains("Message"));
    assert!(text.contains("Child message"));
    assert_eq!(
        text.matches("[embedded frame not readable: ambiguous]")
            .count(),
        2
    );
    assert!(!text.contains("Pair secret"));
    assert!(!text.contains("UNMAPPABLE_INLINE_SECRET"));
    assert!(
        text.find("Child message").unwrap()
            < text
                .find("[embedded frame not readable: ambiguous]")
                .unwrap()
    );
    assert!(!text.contains("pair-one owner"));
    assert!(!text.contains("pair-two owner"));
    for line in text
        .lines()
        .filter(|line| line.contains("[embedded frame not readable:"))
    {
        assert!(
            !line.trim_start().starts_with("ur"),
            "omitted owners must have no ref: {line}"
        );
    }
    let state = fixture.state.lock().unwrap();
    assert_eq!(state.captures, vec!["main", "foreign"]);
    assert!(state.inputs.is_empty());
    let retained = fixture.planes.user_browser.target().state();
    let refs = &retained
        .snapshots
        .get(snapshot["snapshot_id"].as_str().unwrap())
        .unwrap()
        .refs;
    assert!(refs
        .values()
        .all(|reference| !reference.frame.frame_id.starts_with("pair-")
            && ![7, 8].contains(&reference.identity.backend_node_id)));
}

#[tokio::test]
async fn click_on_a_previously_read_element_in_an_omitted_pair_refuses_ambiguity() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    fixture.state.lock().unwrap().frame_pair = true;
    let (before, _) = fixture.snapshot(1, &tab, "allow_30m").await;
    let args = click(&tab, &before, &reference(&before, "pair-one button"));
    fixture.state.lock().unwrap().ambiguous_frames = true;
    let (partial, _) = fixture.snapshot(1, &tab, "allow_30m").await;
    assert_eq!(partial["outcome"], "ok", "{partial}");
    let (zoom, _) = fixture.call(1, json!({"browser":"user","action":"snapshot","tab":tab,"zoom":reference(&before,"pair-one button")}), "allow_30m").await;
    assert_eq!(zoom["outcome"], "ok", "{zoom}");
    assert_eq!(zoom["truncated"], true);
    assert!(zoom["state_text"]
        .as_str()
        .unwrap()
        .contains("[embedded frame not readable: ambiguous]"));
    let (clicked, cards) = fixture.call(1, args, "allow_30m").await;
    assert_eq!(clicked["reason"], "frame_ambiguous", "{clicked}");
    assert_eq!(clicked["input_dispatched"], false);
    assert!(cards.is_empty());
    assert!(fixture.state.lock().unwrap().inputs.is_empty());
}

#[tokio::test]
async fn stray_mapping_without_a_tree_node_does_not_hide_readable_documents() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    fixture.state.lock().unwrap().stray_navigation = true;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_30m").await;
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    assert!(snapshot["state_text"]
        .as_str()
        .unwrap()
        .contains("Child message"));
    assert_eq!(snapshot["truncated"], false);
}

#[tokio::test]
async fn an_unverified_root_navigation_mapping_never_hides_the_top_document() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    fixture.state.lock().unwrap().stale_root_mapping = true;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_30m").await;
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    assert!(snapshot["state_text"].as_str().unwrap().contains("Message"));
}

#[tokio::test]
async fn a_child_changing_again_after_one_retry_is_omitted_from_the_read() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    fixture.state.lock().unwrap().moving_child = true;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_30m").await;
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    assert_eq!(snapshot["truncated"], true);
    assert!(snapshot["state_text"].as_str().unwrap().contains("Message"));
    assert!(snapshot["state_text"]
        .as_str()
        .unwrap()
        .contains("[embedded frame not readable: stale]"));
    assert!(!snapshot["state_text"]
        .as_str()
        .unwrap()
        .contains("Child message"));
    assert_eq!(
        fixture.state.lock().unwrap().captures,
        vec!["main", "foreign", "main", "foreign"]
    );
}

#[tokio::test]
async fn dom_full_keeps_omission_markers_without_unreadable_child_documents() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    {
        let mut state = fixture.state.lock().unwrap();
        state.frame_pair = true;
        state.ambiguous_frames = true;
    }
    let (snapshot, _) = fixture
        .call(
            1,
            json!({"browser":"user","action":"snapshot","tab":tab,"mode":"dom_full"}),
            "allow_30m",
        )
        .await;
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    assert_eq!(snapshot["truncated"], true);
    let text = snapshot["state_text"].as_str().unwrap();
    assert!(text.contains("HTML-main"));
    assert!(text.contains("HTML-foreign"));
    assert_eq!(
        text.matches("[embedded frame not readable: ambiguous]")
            .count(),
        2
    );
    assert!(!text.contains("HTML-pair"));
    assert!(fixture
        .planes
        .user_browser
        .target()
        .state()
        .snapshots
        .get(snapshot["snapshot_id"].as_str().unwrap())
        .unwrap()
        .refs
        .is_empty());
}

#[tokio::test]
async fn a_child_without_an_accessibility_tree_does_not_hide_the_top_page() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    fixture.state.lock().unwrap().child_ax_unavailable = true;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_30m").await;
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    assert_eq!(snapshot["truncated"], true);
    let text = snapshot["state_text"].as_str().unwrap();
    assert!(text.contains("Message"));
    assert!(text.contains("[embedded frame not readable: stale]"));
    assert!(!text.contains("Child message"));
    assert!(!text.contains("Embedded page"));
    let state = fixture.planes.user_browser.target().state();
    let retained = &state.snapshots[snapshot["snapshot_id"].as_str().unwrap()];
    assert!(retained.refs.values().all(|reference| {
        reference.frame.frame_id == "main" && reference.identity.backend_node_id != 6
    }));
}

#[tokio::test]
async fn an_iframe_owner_without_a_discovered_child_is_marked_partial() {
    for mode in ["actionable", "ax", "dom_full"] {
        let fixture = Fixture::new();
        let tab = fixture.claim(1).await;
        {
            let mut state = fixture.state.lock().unwrap();
            state.top_level_only = true;
            state.unmapped_child_owner = true;
        }
        let (snapshot, _) = fixture
            .call(
                1,
                json!({"browser":"user","action":"snapshot","tab":tab,"mode":mode}),
                "allow_30m",
            )
            .await;
        assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
        assert_eq!(snapshot["truncated"], true, "{snapshot}");
        assert_eq!(snapshot["omitted_frames"], 1);
        let text = snapshot["state_text"].as_str().unwrap();
        assert!(
            text.contains("[embedded frame not readable: stale]"),
            "{text}"
        );
        assert!(!text.contains("Embedded page"), "{text}");
        assert!(text.contains(if mode == "dom_full" {
            "HTML-main"
        } else {
            "Message"
        }));
        let state = fixture.planes.user_browser.target().state();
        let retained = &state.snapshots[snapshot["snapshot_id"].as_str().unwrap()];
        assert!(retained
            .refs
            .values()
            .all(|reference| reference.identity.backend_node_id != 6));
    }
}

#[tokio::test]
async fn a_bounded_child_capture_marks_its_iframe_owner_instead_of_silently_cutting_it() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    fixture.state.lock().unwrap().child_ax_oversized = true;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_30m").await;
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    assert_eq!(snapshot["truncated"], true);
    assert_eq!(snapshot["refs_truncated"], true);
    assert_eq!(snapshot["omitted_frames"], 1);
    let text = snapshot["state_text"].as_str().unwrap();
    assert!(text.contains("[embedded frame not readable: stale]"));
    assert!(!text.contains("Embedded page"));
    assert!(!text.contains("Child go"));
}

#[tokio::test]
async fn user_consent_wait_pauses_work_without_lending_unused_park_time() {
    let f = Fixture::new();
    f.state.lock().unwrap().top_level_only = true;
    let tab = f.claim(1).await;
    {
        let mut state = f.state.lock().unwrap();
        state.plan_count = 0;
        state.plan_delay = Duration::from_secs(23);
        state.consent_delay = Duration::from_secs(60);
    }
    tokio::time::pause();
    let start = tokio::time::Instant::now();
    let reply = clocked_reply(
        f.start_arbitrated(json!({
            "browser":"user","action":"snapshot","tab":tab,"mode":"dom_full"
        })),
        190,
    )
    .await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(f.state.lock().unwrap().plan_count, 5);
    assert!(start.elapsed() > Duration::from_millis(crate::budgets::USER_SNAPSHOT.work_ms));
    assert!(
        start.elapsed() <= Duration::from_millis(crate::budgets::USER_SNAPSHOT.work_ms + 60_000)
    );
}

#[tokio::test]
async fn user_deadline_before_dispatch_reports_no_effect_and_no_late_dispatch() {
    let f = Fixture::new();
    let tab = f.claim(1).await;
    {
        let mut state = f.state.lock().unwrap();
        state.hang_attach = true;
        state.plan_count = 0;
    }
    tokio::time::pause();
    let reply = clocked_reply(
        f.start_arbitrated_with_limit(snapshot_args(&tab), Duration::from_secs(1)),
        8,
    )
    .await;
    assert_eq!(reply["outcome"], "action_deadline_exceeded", "{reply}");
    assert_eq!(reply["detail"]["dispatched"], false);
    assert_eq!(f.state.lock().unwrap().plan_count, 0);
}

#[tokio::test]
async fn user_gate_closure_prevents_the_next_plan() {
    let f = Fixture::new();
    let tab = f.claim(1).await;
    f.snapshot(1, &tab, "allow_30m").await;
    {
        let mut state = f.state.lock().unwrap();
        state.plan_count = 0;
        state.attaches = 0;
        state.stop_after_plan = Some(1);
    }
    tokio::time::pause();
    let reply = clocked_reply(f.start_arbitrated(snapshot_args(&tab)), 8).await;
    assert_eq!(reply["outcome"], "action_deadline_exceeded", "{reply}");
    assert_eq!(
        f.state.lock().unwrap().attaches,
        1,
        "no attachment may begin after terminal ownership closes dispatch"
    );
    assert_eq!(f.state.lock().unwrap().plan_count, 1);
}

#[tokio::test]
async fn user_cancel_after_a_mutating_plan_reports_outcome_unknown() {
    let f = Fixture::new();
    let tab = f.claim(1).await;
    let (snapshot, _) = f.snapshot(1, &tab, "allow_30m").await;
    let args = click(&tab, &snapshot, &reference(&snapshot, "Go"));
    {
        let mut state = f.state.lock().unwrap();
        state.plan_count = 0;
        // Debugger-agent setup is read-only. Stop after the mouse gesture so
        // the unknown outcome still proves that actual mutation was admitted.
        state.stop_after_plan = Some(8);
        state.cancel_on_stop = true;
    }
    tokio::time::pause();
    let reply = clocked_reply(f.start_arbitrated(args), 8).await;
    assert_eq!(reply["outcome"], "dispatch_outcome_unknown", "{reply}");
    assert_eq!(reply["detail"]["reason"], "cancelled", "{reply}");
    assert_eq!(reply["detail"]["dispatched"], true);
}

#[test]
fn user_plan_mutation_classification_pins_every_admitted_method() {
    let methods = [
        ("Page.getNavigationHistory", false),
        ("Page.getFrameTree", false),
        ("Page.captureScreenshot", false),
        ("Page.getLayoutMetrics", false),
        ("Accessibility.enable", false),
        ("Accessibility.getFullAXTree", false),
        ("DOM.enable", false),
        ("DOM.getFlattenedDocument", false),
        ("DOM.getOuterHTML", false),
        ("DOM.getContentQuads", false),
        ("DOM.getNodeForLocation", false),
        ("DOM.getFrameOwner", false),
        ("DOM.resolveNode", false),
        ("Runtime.enable", false),
        ("Input.dispatchMouseEvent", true),
        ("Input.dispatchKeyEvent", true),
        ("Input.insertText", true),
        ("DOM.focus", true),
        ("Emulation.setFocusEmulationEnabled", true),
        ("Page.navigate", true),
    ];
    for (method, expected) in methods {
        for child in [false, true] {
            let mut command = command(method, json!({}));
            if child {
                command["frame_id"] = json!("foreign");
                command["loader_id"] = json!("foreign-loader");
                command["session_id"] = json!("child-target");
            }
            assert_eq!(
                mutating_plan(&json!({"action":"cdp", "commands":[command]})),
                expected,
                "{method}, child={child}"
            );
        }
    }
    for declaration in [
        functions::SELECT,
        functions::APPEND_CARET,
        functions::HAS_FOCUS,
        "function() { return true; }",
    ] {
        assert_eq!(
            mutating_plan(
                &json!({"action":"cdp", "commands":[command("Runtime.callFunctionOn", json!({"functionDeclaration":declaration}))]})
            ),
            declaration != functions::HAS_FOCUS,
            "{declaration}"
        );
    }
    assert!(mutating_plan(
        &json!({"action":"cdp","commands":[command("Runtime.callFunctionOn", json!({"functionDeclaration":format!("{} ", functions::HAS_FOCUS)}))]})
    ));
    for method in ["DOM.getDocument", "DOM.describeNode", "DOM.getBoxModel"] {
        assert!(!mutating_plan(
            &json!({"action":"cdp", "commands":[command(method, json!({}))]})
        ));
    }
    assert!(!mutating_plan(&json!({"action":"status"})));
    for action in ["open_tab", "claim_tab", "close", "unknown"] {
        assert!(mutating_plan(&json!({"action":action})), "{action}");
    }
    for method in [
        "DOM.newReadMethod",
        "Runtime.evaluate",
        "Target.setAutoAttach",
        "Page.createIsolatedWorld",
        "",
    ] {
        for child in [false, true] {
            let mut command = command(method, json!({}));
            if child {
                command["frame_id"] = json!("foreign");
                command["loader_id"] = json!("foreign-loader");
                command["session_id"] = json!("child-target");
            }
            assert!(
                mutating_plan(&json!({"action":"cdp", "commands":[command]})),
                "{method}, child={child}"
            );
        }
    }
    assert!(mutating_plan(
        &json!({"action":"cdp","commands":[command("Page.getFrameTree", json!({})), command("Input.insertText", json!({}))]})
    ));
}

#[tokio::test]
async fn user_stuck_mouse_plan_quarantines_the_tab_before_the_next_call() {
    let f = Fixture::new();
    let tab = f.claim(1).await;
    let (snapshot, _) = f.snapshot(1, &tab, "allow_30m").await;
    let args = click(&tab, &snapshot, &reference(&snapshot, "Go"));
    {
        let mut state = f.state.lock().unwrap();
        state.plan_count = 0;
        state.hang_plan = Some(8);
        state.ignore_cancel = true;
    }
    tokio::time::pause();
    let reply = clocked_reply(
        f.start_arbitrated_with_limit(args, Duration::from_secs(1)),
        8,
    )
    .await;
    assert_eq!(reply["outcome"], "dispatch_outcome_unknown", "{reply}");
    assert_eq!(reply["detail"]["held_state"], "unknown", "{reply}");
    let before = f.state.lock().unwrap().attaches;
    let next = clocked_reply(f.start_arbitrated(snapshot_args(&tab)), 8).await;
    assert_eq!(next["outcome"], "target_busy", "{next}");
    assert_eq!(next["detail"]["reason"], "held_input_unconfirmed", "{next}");
    assert_eq!(next["detail"]["dispatched"], false);
    assert_eq!(f.state.lock().unwrap().attaches, before);
}

#[tokio::test]
async fn user_first_claim_keeps_quarantine_until_a_new_connection() {
    let f = Fixture::new();
    {
        let mut state = f.state.lock().unwrap();
        state.hang_action = Some("claim_tab");
        state.ignore_cancel = true;
    }
    tokio::time::pause();
    let reply = clocked_reply(
        f.start_arbitrated_with_limit(
            json!({
                "browser":"user","action":"claim_tab","tab":"handed"
            }),
            Duration::from_secs(1),
        ),
        8,
    )
    .await;
    assert_eq!(reply["outcome"], "dispatch_outcome_unknown", "{reply}");
    assert_eq!(reply["detail"]["held_state"], "none_held");
    let next = clocked_reply(f.start_arbitrated(snapshot_args("handed")), 8).await;
    assert_eq!(next["outcome"], "target_busy", "{next}");
    assert!(next["detail"].get("reason").is_none(), "{next}");
    tokio::time::advance(Duration::from_secs(3)).await;
    until(|| f.planes.user_browser.connected_epoch().is_none()).await;
    let (epoch, _commands) = f.planes.user_browser.connect_for_policy_test();
    // A new extension connection has detached all work from the old one and
    // rotates tab handles; old quarantine must not mask normal ownership checks.
    let frame = tool_frame(1, 999, snapshot_args("handed"));
    let arrival = crate::browser_queue::arrive(&frame, &f.planes);
    let registration = f.planes.cancellations.register((1, 1, 999));
    let lane =
        crate::browser_queue::scope(arrival, crate::browser_queue::enter(&frame, &f.planes)).await;
    assert!(lane.is_ok());
    let unclaimed = f
        .planes
        .user_browser
        .target()
        .owned(
            Route {
                channel: 1,
                epoch: 1,
            },
            "handed",
            epoch,
        )
        .unwrap_err();
    assert_eq!(unclaimed["reason"], "tab_not_claimed_by_route");
    drop(lane);
    drop(registration);
}

#[tokio::test]
async fn child_frame_reads_never_mark_the_call_dispatched() {
    for mode in ["actionable", "ax", "dom_full"] {
        let f = Fixture::new();
        let tab = f.claim(1).await;
        f.state.lock().unwrap().commands.clear();
        let reply = f
            .finish(f.start_arbitrated(
                json!({"browser":"user","action":"snapshot","tab":tab,"mode":mode}),
            ))
            .await;
        assert_eq!(reply["outcome"], "ok", "{reply}");
        let state = f.state.lock().unwrap();
        assert!(state
            .commands
            .iter()
            .any(
                |plan| plan["commands"].as_array().is_some_and(|commands| commands
                    .iter()
                    .any(|command| command["frame_id"] == "foreign"
                        && command["session_id"] == "child-target"))
            ));
        assert!(state.commands.iter().all(|plan| !mutating_plan(plan)));
        let terminal = state.terminal.as_ref().unwrap();
        assert!(
            !terminal.gate_dispatched.load(Ordering::SeqCst),
            "{mode} read entered the mutation gate"
        );
        assert!(
            !terminal.witness.committed(),
            "{mode} read committed the dispatch witness"
        );
        assert!(
            !state
                .terminal
                .as_ref()
                .unwrap()
                .state
                .lock()
                .unwrap()
                .possibly_dispatched,
            "{mode} read marked terminal dispatch"
        );
        assert!(state.inputs.is_empty());
    }
}

#[tokio::test]
async fn child_click_and_type_pass_through_the_mutating_dispatch_gate() {
    for action in ["click", "type"] {
        let f = Fixture::new();
        let tab = f.claim(1).await;
        let (snapshot, _) = f.snapshot(1, &tab, "allow_30m").await;
        let args = if action == "click" {
            click(&tab, &snapshot, &reference(&snapshot, "Child go"))
        } else {
            json!({"browser":"user","action":"type","tab":tab,"ref":reference(&snapshot,"Child message"),"text":"hello"})
        };
        f.state.lock().unwrap().commands.clear();
        let reply = f.finish(f.start_arbitrated(args)).await;
        assert_eq!(reply["outcome"], "ok", "{reply}");
        let state = f.state.lock().unwrap();
        assert!(
            state
                .terminal
                .as_ref()
                .unwrap()
                .gate_dispatched
                .load(Ordering::SeqCst),
            "{action} bypassed the mutating dispatch gate"
        );
        assert!(
            state
                .terminal
                .as_ref()
                .unwrap()
                .state
                .lock()
                .unwrap()
                .possibly_dispatched,
            "{action} bypassed the terminal dispatch gate"
        );
        let mutations: Vec<_> = state
            .commands
            .iter()
            .filter(|plan| mutating_plan(plan))
            .collect();
        assert!(!mutations.is_empty());
        assert!(mutations.iter().all(|plan| plan["commands"]
            .as_array()
            .unwrap()
            .iter()
            .all(|command| command["frame_id"] == "foreign"
                && command["session_id"] == "child-target")));
        let expected = if action == "click" {
            "Input.dispatchMouseEvent"
        } else {
            "Input.insertText"
        };
        assert!(state.inputs.iter().any(|method| method == expected));
    }
}

#[tokio::test]
async fn child_read_plans_spend_the_parent_actions_remaining_allowance() {
    let f = Fixture::new();
    let tab = f.claim(1).await;
    f.snapshot(1, &tab, "allow_30m").await;
    {
        let mut state = f.state.lock().unwrap();
        state.commands.clear();
        state.plan_count = 0;
        state.plan_delay = Duration::from_secs(23);
    }
    tokio::time::pause();
    let start = tokio::time::Instant::now();
    let allowance = crate::budgets::USER_SNAPSHOT.work_ms;
    let reply = clocked_reply(
        f.start_arbitrated(
            json!({"browser":"user","action":"snapshot","tab":tab,"mode":"dom_full"}),
        ),
        allowance / 1000 + 6,
    )
    .await;
    assert_eq!(reply["outcome"], "action_deadline_exceeded", "{reply}");
    assert_eq!(reply["detail"]["dispatched"], false);
    assert!(start.elapsed() >= Duration::from_millis(allowance));
    assert!(start.elapsed() <= Duration::from_millis(allowance + 1_000));
    let completed = {
        let state = f.state.lock().unwrap();
        assert!(state
            .commands
            .iter()
            .any(
                |plan| plan["commands"].as_array().is_some_and(|commands| commands
                    .iter()
                    .any(|command| command["frame_id"] == "foreign"
                        && command["session_id"] == "child-target"))
            ));
        assert!(
            state.plan_count < 8,
            "the child must not receive time for a fresh eight-plan snapshot"
        );
        state.plan_count
    };
    tokio::time::advance(Duration::from_secs(30)).await;
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        f.state.lock().unwrap().plan_count,
        completed,
        "late child replies must not resume work"
    );
}

#[tokio::test]
async fn child_type_keeps_the_same_deadline_after_switching_sessions() {
    let f = Fixture::new();
    let tab = f.claim(1).await;
    let (snapshot, _) = f.snapshot(1, &tab, "allow_30m").await;
    let args = json!({"browser":"user","action":"type","tab":tab,"ref":reference(&snapshot,"Child message"),"text":"hello"});
    let (warmup, _) = f.call(1, args.clone(), "allow_30m").await;
    assert_eq!(warmup["outcome"], "ok", "{warmup}");
    {
        let mut state = f.state.lock().unwrap();
        state.commands.clear();
        state.plan_count = 0;
        state.plan_delay = Duration::from_secs(27);
        state.hang_plan = Some(10);
    }
    tokio::time::pause();
    let start = tokio::time::Instant::now();
    let allowance = crate::budgets::USER_TYPE.work_ms;
    let reply = clocked_reply(f.start_arbitrated(args), allowance / 1000 + 6).await;
    assert_eq!(reply["outcome"], "dispatch_outcome_unknown", "{reply}");
    assert_eq!(reply["detail"]["reason"], "action_deadline_exceeded");
    assert_eq!(reply["detail"]["dispatched"], true);
    assert!(start.elapsed() >= Duration::from_millis(allowance));
    assert!(start.elapsed() <= Duration::from_millis(allowance + 1_000));
    let state = f.state.lock().unwrap();
    assert_eq!(state.plan_count, 10);
    assert!(state
        .commands
        .iter()
        .filter(|plan| mutating_plan(plan))
        .all(|plan| plan["commands"]
            .as_array()
            .unwrap()
            .iter()
            .all(|command| command["frame_id"] == "foreign"
                && command["session_id"] == "child-target")));
}
