//! What a model reads after every `browser_use` and `computer_use` action, on a
//! route that declares it reads tool-result/v1 results.
//!
//! A tool-result/v1 reader shows the model only a reply's text and image parts;
//! the operator ruled that no JSON may reach the model that way, and a reader
//! that finds no text shows the structured copy as JSON instead. These tests
//! drive each action through the production frame loop and the real handlers,
//! successes and refusals alike, and hold every reply to
//! [`crate::tool_result::model_view_problems`]: some plain text, and no JSON
//! object or array anywhere in it. The reply inventories in
//! `computer_capability::outcome_tests` cover the shapes only a fault or a
//! platform refusal produces.

use super::*;
use crate::test_support::HANG_GUARD;

const CHANNEL: u16 = 7;
const EPOCH: u32 = 1;

/// Bind the test route as a session caller whose consumer declares that it
/// reads tool-result/v1 results (and can relay a consent question).
fn bind_content_reader(planes: &Planes) {
    planes.routes.insert(
        CHANNEL,
        EPOCH,
        AcceptedBindFacts::from_bind(
            &subc_protocol::BindIdentity::new("/test/project", "test", "test-session".to_string()),
            session_caller_principal_for_test(),
            Some(&json!({
                "agentProjectId": "test-project",
                "sessionKind": "primary",
                      "effectiveCapabilityScope": ["*"],
                      "browserControlOperations": [crate::browser_session::BROWSER_STATUS],
            })),
            Some(&[
                "elicitation".to_string(),
                cortexkit_role_tool_provider::TOOL_RESULT_V1_CAPABILITY.to_string(),
            ]),
            &subc_protocol::RouteTarget::ToolProvider {
                module_id: "cerebellum".to_string(),
            },
        ),
    );
}

fn request(corr: u64, tool: &str, arguments: Value) -> Frame {
    Frame::build(
        FrameType::Request,
        control_flags(),
        CHANNEL,
        EPOCH,
        corr,
        serde_json::to_vec(&json!({"name": tool, "arguments": arguments})).unwrap(),
    )
    .unwrap()
}

/// Every reply a call produced, checked: each must be a valid tool-result/v1
/// result whose text passes the model-view guard. Returns the decoded results
/// so a test can also check what a particular reply says.
#[derive(Default)]
struct Views {
    results: Vec<(String, Value)>,
    failures: Vec<String>,
}

impl Views {
    fn check(&mut self, action: &str, label: &str, frame: &Frame) -> Value {
        assert_eq!(
            frame.header.ty,
            FrameType::Response,
            "{label}: {}",
            String::from_utf8_lossy(&frame.body)
        );
        let result: Value = serde_json::from_slice(&frame.body).unwrap();
        let typed: cortexkit_role_tool_provider::result::ToolResult =
            serde_json::from_value(result.clone())
                .unwrap_or_else(|error| panic!("{label}: not a tool-result/v1 result: {error}"));
        cortexkit_role_tool_provider::result::validate(&typed).unwrap();
        for problem in crate::tool_result::model_view_problems_for_action(&result, action) {
            self.failures.push(format!("{label}: {problem}"));
        }
        self.results.push((label.to_string(), result.clone()));
        println!(
            "MODEL_VIEW AUDIT {label} [{action}]: {}",
            texts(&result).replace('\n', " | ")
        );
        result
    }

    fn assert_clean(&self) {
        assert!(self.failures.is_empty(), "{}", self.failures.join("\n"));
    }
}

fn texts(result: &Value) -> String {
    result["content"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|part| part["text"].as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Each `browser_use` action with the fields it requires, plus a call naming
/// an unknown field. No browser runs here, so most end in a refusal; those
/// are the replies a model most needs to read plainly.
fn browser_calls() -> Vec<(&'static str, Value)> {
    let severity = json!({"tier": 1, "credential": false, "financial": false});
    vec![
        ("launch", json!({})),
        ("open_tab", json!({"browser": "user"})),
        ("claim_tab", json!({"browser": "user", "tab": "tab-1"})),
        ("status", json!({})),
        ("status", json!({"browser": "user"})),
        ("close", json!({"browser_session_id": "session-1"})),
        (
            "navigate",
            json!({"url": "https://example.com/", "intent": "read", "severity": severity}),
        ),
        ("snapshot", json!({})),
        ("screenshot", json!({})),
        ("scroll", json!({"direction": "down"})),
        (
            "click",
            json!({"ref": "e1", "snapshot_id": "snapshot-1", "intent": "open", "severity": severity}),
        ),
        ("type", json!({"ref": "e1", "text": "hello"})),
        (
            "click_point",
            json!({"point": {"x": 1, "y": 1}, "snapshot_id": "snapshot-1", "image_width_px": 10,
                "image_height_px": 10, "intent": "open", "severity": severity}),
        ),
        (
            "open_grant",
            json!({"origins": ["https://example.com"], "hazards": []}),
        ),
        ("present", json!({"origin": "https://example.com"})),
        ("resume", json!({})),
        ("import_login", json!({"origin": "https://example.com"})),
        (
            "capture_login",
            json!({"credential_domain": "example.com", "account": "a", "fetch_url":
                "https://example.com/me", "login_url": "https://example.com/login"}),
        ),
        ("revoke_access", json!({})),
        ("snapshot", json!({"browser": "user", "tab": "tab-1"})),
    ]
}

#[tokio::test]
async fn every_browser_action_reads_as_plain_words() {
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    bind_content_reader(&planes);
    let mut views = Views::default();
    let mut corr = 100;
    for (action, mut arguments) in browser_calls() {
        arguments["action"] = json!(action);
        corr += 1;
        let (tx, mut rx) = mpsc::channel(8);
        handle_frame(
            request(corr, flat_tools::BROWSER_USE, arguments.clone()),
            &tx,
            &planes,
        )
        .await
        .unwrap();
        let frame = tokio::time::timeout(HANG_GUARD, rx.recv())
            .await
            .unwrap_or_else(|_| panic!("browser {action} never answered"))
            .unwrap();
        // A request the flat tool refuses before dispatch is a route error,
        // not a tool result, and carries no model view of its own.
        if frame.header.ty == FrameType::Response {
            views.check(action, &format!("browser {action} {arguments}"), &frame);
        }
    }
    views.assert_clean();
    let snapshot = views
        .results
        .iter()
        .find(|(label, _)| label.starts_with("browser snapshot {\"action\":\"snapshot\"}"))
        .map(|(_, result)| texts(result))
        .expect("the snapshot call produced a tool result");
    assert_eq!(
        snapshot,
        "No session.\nCall browser.launch, then retry the browser action.\nReason: no browser session is open."
    );
    assert!(
        views.results.len() >= browser_calls().len() - 2,
        "most browser calls produced a tool result: {}",
        views.results.len()
    );
}

// The computer plane is served on macOS only, so this half runs there. Its
// `Planes` setup, the way it answers consent cards, and its use of
// COMPUTER_CONSENT_PARK_LIMIT_FOR_TEST (how long a call waits for a consent
// answer before replying consent_pending) are copied from
// `computer_consent_wire_tests` and `relayed_computer_call_tests`.
#[cfg(target_os = "macos")]
mod computer {
    use super::*;
    use cerebellum_computer::app_state::source::{
        AppStateReadError, AppStateSource, BundleSignature, ElementActionError, ElementFacts,
        ElementHandle, ElementValue, HitScope, InstalledApp, InstalledApps, OpenAppBounds,
        OpenedApp, RawAppState, RawElement, ReadBounds, RunningApp,
    };
    use cerebellum_computer::platform::{ProcessGrant, TargetResolution};

    const DASHBOARD: &str = "com.example.dashboard";

    struct Running;

    impl management::TargetResolver for Running {
        fn resolve(&self, bundle_identity: &str) -> TargetResolution {
            TargetResolution::Resolved(ProcessGrant {
                pid: 4242,
                bundle_identity: bundle_identity.to_string(),
                process_generation_evidence: "1700000000000000".to_string(),
            })
        }

        fn app_code(&self, _grant: &ProcessGrant) -> Arc<dyn computer_grants::AppCode> {
            Arc::new(computer_grants::SignedByFixtureTeam)
        }
    }

    /// A desk with a dashboard whose window holds a short table, a text field
    /// and a button, two other running applications and two installed ones.
    struct Desk;

    fn installed(name: &str, bundle_identity: &str) -> InstalledApp {
        InstalledApp {
            name: name.into(),
            bundle_identity: bundle_identity.into(),
            path: format!("/Applications/{name}.app").into(),
        }
    }

    impl AppStateSource for Desk {
        fn read_app_state(
            &self,
            _target: &ProcessGrant,
            _bounds: ReadBounds,
        ) -> Result<RawAppState, AppStateReadError> {
            let token = std::cell::Cell::new(0);
            let element = |role: &str| {
                token.set(token.get() + 1);
                RawElement::fixture(token.get(), role)
            };
            let text = |value: &str| {
                let mut text = element("AXStaticText");
                text.value = ElementValue::Text(value.into());
                text
            };
            let rows = (0..2)
                .map(|row| {
                    let first = text(&format!("Memory {row}"));
                    let second = text("Maps each memory to its source");
                    element("AXRow").with_children(vec![
                        element("AXCell").with_children(vec![first]),
                        element("AXCell").with_children(vec![second]),
                    ])
                })
                .collect();
            let table = element("AXTable").titled("Memories").with_children(rows);
            let mut field = element("AXTextField").titled("Search");
            field.value_settable = true;
            field.value = ElementValue::Text("draft".into());
            let save = element("AXButton").titled("Save");
            let window = element("AXWindow")
                .titled("Dashboard")
                .with_children(vec![table, field, save]);
            Ok(RawAppState {
                roots: vec![window],
                focused: None,
                unreadable_subtrees: 0,
                read_bound_reached: false,
            })
        }

        fn element_facts(&self, _: &ElementHandle) -> Result<ElementFacts, ElementActionError> {
            Ok(ElementFacts {
                pid: Some(4242),
                role: Some("AXButton".into()),
                subrole: None,
                title: Some("Save".into()),
                actions: vec!["AXPress".into()],
                value_settable: false,
                selected_text_settable: false,
            })
        }

        fn press(&self, _: &ElementHandle) -> Result<(), ElementActionError> {
            Ok(())
        }

        fn element_at(
            &self,
            _: HitScope,
            _: (f64, f64),
        ) -> Result<Option<(ElementHandle, Option<u32>)>, ElementActionError> {
            Ok(None)
        }

        fn running_apps(&self) -> Result<Vec<RunningApp>, AppStateReadError> {
            Ok([
                ("Magic Context Dashboard", DASHBOARD, true),
                ("Magic Mouse Utility", "com.example.mouse", false),
                ("Mail", "com.apple.mail", false),
            ]
            .into_iter()
            .enumerate()
            .map(|(index, (name, bundle_identity, frontmost))| RunningApp {
                name: name.into(),
                bundle_identity: bundle_identity.into(),
                pid: 4242 + index as u32,
                frontmost,
            })
            .collect())
        }

        fn installed_apps(&self, _: Duration) -> InstalledApps {
            InstalledApps {
                apps: vec![
                    installed("Magic Context Dashboard", DASHBOARD),
                    installed("Calculator", "com.apple.calculator"),
                    installed("Chess", "com.apple.Chess"),
                ],
                complete: true,
            }
        }

        fn bundle_signature(&self, _: &InstalledApp) -> Result<BundleSignature, AppStateReadError> {
            Ok(BundleSignature {
                signed: true,
                ad_hoc: false,
                team_id: Some("fixture-team".into()),
                designated_requirement: Some("fixture-requirement".into()),
                apple_anchored: false,
            })
        }

        fn bundle_satisfies(&self, _: &InstalledApp, _: &str) -> bool {
            true
        }

        fn open_app(
            &self,
            _: &InstalledApp,
            _: OpenAppBounds,
        ) -> Result<OpenedApp, cerebellum_computer::app_state::source::OpenAppError> {
            Ok(OpenedApp {
                pid: 4300,
                already_running: false,
                has_window: true,
                frontmost: false,
                process_started_ms: 50,
                first_window_ms: Some(100),
            })
        }
    }

    fn planes() -> Planes {
        let mut planes = Planes::with_browser_config_journaling(
            Arc::new(HealthState::default()),
            None,
            JournalPersistence::Isolated,
        );
        planes.management = Arc::new(ManagementPlane::new(Arc::new(Running)));
        // The screen is pinned unlocked: a locked developer machine would
        // refuse every call before it reads anything.
        planes.computer =
            computer_capability::computer_audit(JournalPersistence::Isolated).map(|audit| {
                Arc::new(
                    computer_capability::ComputerPlane::with_synthetic_driver(audit, || {
                        computer_capability::NativeComputerPlatformDriver::default()
                            .without_expected_post_condition()
                    })
                    .with_permission_liveness(computer_capability::live_for_test())
                    .with_session_lock_for_test(Some(false))
                    .with_app_state_source(Arc::new(Desk)),
                )
            });
        // A test build binds no release attestations, so its default admitted
        // set (`test_admitted_computer_capabilities`) is only computer.wait,
        // and an unadmitted capability is refused before dispatch. Name every
        // action the walk sends, as `relayed_computer_call_tests` names
        // read_state.
        planes.computer_admitted = Arc::new(
            [
                "computer.read_state",
                "computer.list_apps",
                "computer.press_element",
                "computer.press_point",
                "computer.write_text",
                "computer.type",
                "computer.keys",
                "computer.takeover_move",
                "computer.wait",
                "computer.open_app",
            ]
            .map(String::from)
            .into(),
        );
        bind_content_reader(&planes);
        computer_grants::tests::CardService::install(planes, CHANNEL, EPOCH)
    }

    /// Send one `computer_use` call and return its reply, allowing every
    /// consent question it puts while it waits.
    ///
    /// `CardService::card` panics with "Cingulate received no card" only after
    /// `HANG_GUARD`, so it is only ever awaited here in short slices that are
    /// dropped when they find nothing: a call that is slow without asking anything
    /// must not read as a missing card.
    async fn call(planes: &Planes, corr: u64, arguments: Value) -> Frame {
        let label = arguments.to_string();
        let (tx, mut rx) = mpsc::channel(8);
        handle_frame(
            request(corr, flat_tools::COMPUTER_USE, arguments),
            &tx,
            planes,
        )
        .await
        .unwrap();
        let consent = planes.consent_test.as_ref().unwrap();
        let deadline = tokio::time::Instant::now() + HANG_GUARD;
        loop {
            if let Ok(frame) = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {
                return frame.expect("the reply channel stayed open");
            }
            // `card` takes a card off the queue only when it returns one, so
            // dropping the slice when it times out loses nothing.
            if let Ok(question) =
                tokio::time::timeout(Duration::from_millis(100), consent.card(CHANNEL, EPOCH)).await
            {
                consent.answer(
                    question.header.corr,
                    cingulate_client::ScriptedAnswer::Answered(json!({"decision": "allow_30m"})),
                );
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "computer call {label} did not reply before the test hang guard"
            );
        }
    }

    /// The element id on the first line of `text` that contains `needle`.
    fn id_of(text: &str, needle: &str) -> String {
        text.lines()
            .find(|line| line.contains(needle))
            .and_then(|line| line.split_whitespace().next())
            .unwrap_or_else(|| panic!("no line with {needle} in {text}"))
            .to_string()
    }

    /// The route's caller and the app grant a read of `bundle_identity`
    /// needs, built as `computer_consent_wire_tests::stack_tests` builds them.
    fn dashboard_grant(
        planes: &Planes,
    ) -> (computer_grants::GrantCaller, computer_grants::GrantNeed) {
        let facts = planes.routes.get(CHANNEL, EPOCH).unwrap();
        let caller = computer_grants::GrantCaller {
            holder: permission_scope::authorizing_holder(&facts),
            conversation_key: facts.identity.conversation_key,
            agent_project_id: facts.identity.agent_project_id,
            durable_identity_attested: true,
        };
        let need = computer_grants::GrantNeed::App {
            bundle_identity: DASHBOARD.into(),
            display_name: DASHBOARD.into(),
            code: Arc::new(computer_grants::SignedByFixtureTeam),
        };
        (caller, need)
    }

    // Only calls whose work stays inside the `Desk` fixture are sent. The
    // plane on `Planes` is built over the real macOS input driver and capture
    // backend, so typing, keys, takeover pointer actions, waits, window
    // images and launches would post real input to, read, or start real
    // processes on the host running the test. Their reply shapes are held to
    // the same model-view rule through the production reply builders in
    // `computer_capability::outcome_tests`.
    #[tokio::test]
    async fn every_computer_action_reads_as_plain_words() {
        let planes = planes();
        let mut views = Views::default();
        let (caller, need) = dashboard_grant(&planes);
        let grants = planes.management.computer_grants();
        assert!(
            !grants.holds(&caller, &need),
            "a fresh plane already holds the dashboard grant, so no card would be asked"
        );

        // The first read of the dashboard, which nothing has granted, asks
        // the person. Waiting at most 20 ms for the answer, it replies
        // consent_pending; the card it put is answered afterwards, which
        // records the grant for the calls that follow. The pattern is
        // `stack_tests::withdraw_asked_call_and_apply_late_grant`'s.
        let (tx, mut rx) = mpsc::channel(8);
        COMPUTER_CONSENT_PARK_LIMIT_FOR_TEST
            .scope(
                Duration::from_millis(20),
                computer_grants::tests::with_live(
                    handle_tool_request_for_test_with_existing_planes(
                        request(
                            1,
                            flat_tools::COMPUTER_USE,
                            json!({"action": "read_state", "target": "Magic Context"}),
                        ),
                        &tx,
                        &planes,
                    ),
                ),
            )
            .await
            .unwrap();
        // Read the reply before looking for the card, so a read that did not
        // ask fails here naming what it replied instead.
        let reply = tokio::time::timeout(HANG_GUARD, rx.recv())
            .await
            .expect("the parked read replied")
            .unwrap();
        let pending = views.check("read_state", "read_state while consent is pending", &reply);
        assert_eq!(
            pending["structuredContent"]["outcome"], "consent_pending",
            "the first read of an ungranted app must ask: {pending}"
        );
        assert!(
            texts(&pending).contains("Waiting for the person"),
            "{pending}"
        );
        // The read replied consent_pending, so its card is on the queue.
        let consent = planes.consent_test.as_ref().unwrap();
        let question = consent.card(CHANNEL, EPOCH).await;
        assert!(consent.answer(
            question.header.corr,
            cingulate_client::ScriptedAnswer::Answered(json!({"decision": "allow_30m"})),
        ));
        computer_grants::tests::drain_call(&planes, CHANNEL, EPOCH).await;
        tokio::time::timeout(HANG_GUARD, async {
            while !grants.holds(&caller, &need) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the late answer records the dashboard grant");

        let mut corr = 10;
        let mut next = |arguments: Value| {
            corr += 1;
            (corr, arguments)
        };

        let (id, arguments) = next(json!({"action": "read_state", "target": "Magic Context"}));
        let read = views.check(
            "read_state",
            "read_state by partial name",
            &call(&planes, id, arguments).await,
        );
        assert_eq!(read["structuredContent"]["outcome"], "completed", "{read}");
        assert_eq!(
            read["structuredContent"]["matched_app"],
            "Magic Context Dashboard"
        );
        let read_text = texts(&read);
        assert!(
            read_text.contains("Using the running app Magic Context Dashboard."),
            "{read_text}"
        );
        assert!(read_text.contains(" cell Memory 0"), "{read_text}");
        let facts = planes.routes.get(CHANNEL, EPOCH).unwrap();
        let scope = facts
            .scope
            .map(|stamp| stamp.scope_ref)
            .unwrap_or(facts.identity.conversation_key);
        assert_eq!(
            crate::private_content_marks_tests::query(&planes, &scope).await,
            json!({"private_content":true,"sources":["desktop_app"]})
        );
        let save = id_of(&read_text, "button Save");
        let field = id_of(&read_text, "text field");

        let (id, arguments) = next(json!({"action": "list_apps"}));
        let listed = views.check(
            "list_apps",
            "list_apps",
            &call(&planes, id, arguments).await,
        );
        assert!(
            texts(&listed).starts_with("Running apps:\nMagic Context Dashboard · com.example.dashboard · pid 4242 · frontmost\n"),
            "{listed}"
        );

        let calls = [
            json!({"action": "list_apps", "text_filter": "calc"}),
            json!({"action": "list_apps", "zoom": "x"}),
            json!({"action": "read_state", "target": "Magic"}),
            json!({"action": "read_state", "target": "Nobody"}),
            json!({"action": "read_state", "target": DASHBOARD, "text_filter": "Memory"}),
            json!({"action": "read_state", "target": DASHBOARD, "zoom": "nope"}),
            json!({"action": "read_state", "target": DASHBOARD, "bogus": 1}),
            json!({"action": "press_element", "element_id": save}),
            json!({"action": "press_element", "element_ids": [save, "missing-id"]}),
            json!({"action": "press_point", "image_id": "image-unknown", "x": 1, "y": 1}),
            json!({"action": "write_text", "element_id": field, "text": "hello", "write_mode": "replace_value"}),
            json!({"action": "type", "target": DASHBOARD}),
            json!({"action": "keys", "target": DASHBOARD}),
            json!({"action": "takeover_move"}),
            json!({"action": "wait", "app": DASHBOARD}),
            json!({"action": "open_app", "target": "Nothing Installed"}),
        ];
        let sent = calls.len();
        let mut answered = 0;
        for arguments in calls {
            let (id, arguments) = next(arguments);
            let label = format!("computer {arguments}");
            let action = arguments["action"].as_str().unwrap_or("unknown").to_owned();
            let frame = call(&planes, id, arguments).await;
            // A request the flat tool refuses before dispatch (a missing
            // required field) is a route error, not a tool result, and
            // carries no model view of its own.
            if frame.header.ty == FrameType::Response {
                views.check(&action, &label, &frame);
                answered += 1;
            }
        }
        assert!(
            answered >= sent / 2,
            "most computer calls produced a tool result: {answered} of {sent}"
        );
        let outcomes: std::collections::BTreeSet<String> = views
            .results
            .iter()
            .filter_map(|(_, result)| {
                result["structuredContent"]["outcome"]
                    .as_str()
                    .map(str::to_owned)
            })
            .collect();
        // The calls above produced successes as well as refusals, so the
        // model-view check below judged both kinds of reply.
        for expected in [
            "completed",
            "consent_pending",
            "ambiguous_app",
            "no_running_app_named",
            "invalid_request",
        ] {
            assert!(
                outcomes.contains(expected),
                "{expected} not reached: {outcomes:?}"
            );
        }
        views.assert_clean();
    }
}
