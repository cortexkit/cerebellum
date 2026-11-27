#[path = "tests/capture_audit_tests.rs"]
mod capture_audit_tests;
#[path = "tests/capture_cancel_tests.rs"]
mod capture_cancel_tests;
use crate::test_support::HANG_GUARD;
#[tokio::test]
async fn isolated_plane_without_profile_lifecycle_refuses_rebind_without_touching_data_home() {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;

    fn snapshot(root: &std::path::Path) -> BTreeMap<PathBuf, Option<std::time::SystemTime>> {
        let mut entries = BTreeMap::new();
        let Ok(children) = fs::read_dir(root) else {
            return entries;
        };
        for child in children.flatten() {
            let path = child.path();
            let modified = child
                .metadata()
                .ok()
                .and_then(|metadata| metadata.modified().ok());
            entries.insert(path, modified);
        }
        entries
    }

    let data_home = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")));
    let browser_root = data_home.map(|root| root.join("cortexkit/cerebellum/browser"));
    let before = browser_root.as_deref().map(snapshot);

    let planes = Planes::new(Arc::new(HealthState::new()));
    let (reply, question) = planes
        .management
        .open_profile_root_rebind("isolated-rebind-test", true)
        .await;
    assert_eq!(reply["outcome"], "internal_failure");
    assert_eq!(reply["stage"], "profile_registry_unavailable");
    assert!(question.is_none());
    if let (Some(root), Some(before)) = (browser_root, before) {
        assert_eq!(
            snapshot(&root),
            before,
            "isolated rebind touched the operator browser data home"
        );
    }
}

#[test]
fn scope_admission_nondelegating_routes_do_not_read_or_offer_standing_grants() {
    use super::*;
    let core = Principal::Reserved {
        module_id: "prefrontal".into(),
    };
    let bind = subc_protocol::BindIdentity::new("test", "conversation");
    let target = subc_protocol::RouteTarget::ToolProvider {
        module_id: "cerebellum".into(),
    };
    for delegates in [false, true] {
        let scope = subc_protocol::scope::ScopeStamp::new(
            core.clone(),
            "head",
            1,
            subc_protocol::scope::ScopeKind::Head,
        )
        .with_attributes(
            subc_protocol::scope::ScopeAttributes::new()
                .with_agent_id(Some("pj-agent".into()))
                .with_delegates(delegates),
        )
        .with_owner_authorized(true);
        let facts = AcceptedBindFacts::from_bind(&bind, Some(core.clone()), None, None, &target)
            .with_scope(Some(scope));
        assert_eq!(standing_caller(&facts).is_some(), delegates);
        assert_eq!(
            standing_offer_agent(&facts),
            if delegates { Some("pj-agent") } else { None }
        );
        let planes = Planes::with_browser_config_journaling(
            Arc::new(HealthState::new()),
            None,
            JournalPersistence::Isolated,
        );
        let (tx, _) = mpsc::channel(2);
        let consent = consent_context(&planes, &facts, &tx, 9, 3);
        assert_eq!(
            consent.caller.durable_identity_attested, delegates,
            "persistent app grants and Always allow use this same attestation"
        );
    }
}

/// The build script names exactly the attestations the compiler reads.
///
/// The names live in two places: `option_env!` calls here, and exports in
/// the release build script. Nothing else connects them, so a misspelling
/// in either sets or reads a variable the other does not know.
///
/// It fails CLOSED, which is what makes it worth a test: the build
/// succeeds, the capability is silently withheld, and the gate report
/// blames a missing attestation for one that was supplied. Measured before
/// this existed -- a single transposed letter dropped computer.screenshot
/// from a release build with no error anywhere.
///
/// The script rejects an unknown CEREBELLUM_ variable at run time, which
/// catches a typo in the script. This catches the other direction: a name
/// changed here and not there.
#[test]
fn the_release_script_names_every_attestation_the_compiler_reads() {
    let source = concat!(
        include_str!("../lib.rs"),
        include_str!("../control.rs"),
        include_str!("../management_dispatch.rs"),
        include_str!("../tool_dispatch.rs"),
        include_str!("../planes.rs"),
    );
    let script = include_str!("../../../../scripts/release-build.sh");

    let read_here: std::collections::BTreeSet<&str> = source
        .split("option_env!(")
        .skip(1)
        .filter_map(|rest| rest.trim_start().strip_prefix('"'))
        .filter_map(|rest| rest.split('"').next())
        .filter(|name| name.starts_with("CEREBELLUM_"))
        .collect();

    assert!(read_here.contains("CEREBELLUM_TAKEOVER_POINTER_FRONTING_REVIEW_REVISION"));
    assert_eq!(
        read_here.len(),
        13,
        "expected thirteen attestations, found {read_here:?}"
    );

    for name in &read_here {
        assert!(
            script.contains(name),
            "{name} is read by the compiler and absent from the release script, \
             so a release cannot bind it"
        );
    }
}

#[test]
fn configured_browser_advertisement_and_dispatch_match_in_both_directions() {
    let manifest = serialize_manifest_with_browser_configuration(
        "cerebellum",
        &BrowserSurface::Available(browser_surface_config()),
    );
    let advertised: std::collections::BTreeSet<&str> = manifest["provides"]
        .as_array()
        .unwrap()
        .iter()
        .find(|role| role["role"] == "tool_provider")
        .unwrap()["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .filter(|name| name.starts_with("browser."))
        .collect();
    let candidates = browser_session::CONTROL_TOOLS
        .into_iter()
        .chain(browser::ALL_TOOLS)
        .chain(["browser.type"]);
    let dispatchable: std::collections::BTreeSet<&str> = candidates
        .filter(|name| dispatchable_tool_with_browser(name, true).is_some())
        .collect();

    for name in &advertised {
        assert!(
            dispatchable.contains(name),
            "{name} is advertised but undispatchable"
        );
    }
    for name in &dispatchable {
        assert!(
            advertised.contains(name),
            "{name} is dispatchable but unadvertised"
        );
    }
    // click_point is admitted: its mapping is verified against a live
    // browser, which is what it was held back for. A page click listener
    // recorded (600,476) css where the module's mapping predicts 476.75 --
    // page truncation against probe rounding, not a mapping error, and a
    // scale error would have shown as a factor rather than a fraction.
    assert!(dispatchable.contains(browser::CLICK_POINT));
    // Ordinary form composition is admitted; credential fields still refuse.
    assert!(dispatchable.contains(browser::TYPE));
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn withheld_actions_are_refused_by_the_adapter_too() {
    let keys_frame = || {
        let request = json!({
            "name": flat_tools::COMPUTER_USE,
            "arguments": {
                "action": "keys",
                "keys": ["s"],
                "target": "com.example.Editor"
            }
        });
        Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            7,
            1,
            99,
            serde_json::to_vec(&request).unwrap(),
        )
        .unwrap()
    };
    let refusal = |admitted: &'static [&'static str]| {
        let frame = keys_frame();
        async move {
            let (tx, mut rx) = mpsc::channel(1);
            let health = Arc::new(HealthState::new());
            handle_tool_request_for_test_admitting(frame, &tx, &health, admitted)
                .await
                .unwrap();
            let reply = rx.recv().await.expect("one refusal");
            assert_eq!(reply.header.ty, FrameType::Error);
            serde_json::from_slice::<ErrorBody>(&reply.body)
                .unwrap()
                .code
        }
    };
    // With some computer action admitted the tool is served, so the one
    // withheld action is refused by name at the adapter.
    assert_eq!(
        refusal(&["computer.read_state"]).await,
        "capability_not_admitted"
    );
    // With nothing admitted the catalog omits computer_use entirely, and
    // tool-provider/v1 refuses a call to an omitted tool as disabled.
    assert_eq!(refusal(&[]).await, "tool_disabled");
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn folded_management_actions_match_the_management_route_on_the_same_bind() {
    let cases = [
        (
            flat_tools::BROWSER_USE,
            "open_grant",
            management::OPEN_GRANT,
            json!({"origins":["https://example.com"],"hazards":[]}),
        ),
        (
            flat_tools::BROWSER_USE,
            "present",
            management::PRESENT,
            json!({"origin":"https://example.com"}),
        ),
        (
            flat_tools::BROWSER_USE,
            "resume",
            management::RESUME,
            json!({}),
        ),
        (
            flat_tools::BROWSER_USE,
            "import_login",
            management::IMPORT_LOGIN,
            json!({"origin":"https://example.com"}),
        ),
    ];

    for (flat_name, action, method, params) in cases {
        let channel = 23;
        let epoch = 4;
        let mut planes = management_bound_planes(channel, epoch);
        planes.browser_config = Some(browser_surface_config());
        planes.management = Arc::new(ManagementPlane::new(Arc::new(OneRunning)));
        let facts = AcceptedBindFacts::from_bind(
            &bind_identity_for_test(),
            session_caller_principal_for_test(),
            Some(&json!({
                "agentProjectId": "test-project",
                "sessionKind": "primary",
                "effectiveCapabilityScope": ["*"]
            })),
            None,
            &subc_protocol::RouteTarget::ToolProvider {
                module_id: "cerebellum".into(),
            },
        );
        planes.routes.insert(channel, epoch, facts.clone());

        let mut flat_arguments = params.clone();
        flat_arguments["action"] = json!(action);
        let flat_frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            channel,
            epoch,
            101,
            serde_json::to_vec(&json!({
                "name": flat_name,
                "arguments": flat_arguments,
            }))
            .unwrap(),
        )
        .unwrap();
        let management_frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            channel,
            epoch,
            102,
            serde_json::to_vec(&json!({"method":method,"params":params})).unwrap(),
        )
        .unwrap();
        let (tx, mut rx) = mpsc::channel(2);
        handle_tool_request(flat_frame, &tx, &planes, &CallObservation::new())
            .await
            .unwrap();
        handle_management_request(management_frame, &tx, &facts, &planes)
            .await
            .unwrap();
        let flat_reply: Value = serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
        let management_reply: Value =
            serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
        assert_eq!(flat_reply, management_reply, "{action} diverged");
        if action == "import_login" {
            assert_eq!(flat_reply["outcome"], "consent_unavailable");
            assert_eq!(flat_reply["detail"]["reason"], "no_agent_session");
        }
    }
}

#[test]
fn in_flight_bound_covers_the_longest_work_and_release() {
    assert_eq!(
        budgets::IN_FLIGHT_AGE_STALE_MS,
        budgets::MAX_ACTION_WORK_MS + budgets::RELEASE_BUDGET_MS + budgets::IN_FLIGHT_MARGIN_MS
    );
}

fn browser_surface_config() -> BrowserConfig {
    BrowserConfig {
        executable_path: None,
        expected_identity: None,
        launch_handshake_deadline_ms: 100,
        termination_grace_period_ms: 100,
        browser_idle_timeout_ms: 30_000,
        browser_exit_observation_deadline_ms: 100,
        navigation_settle_deadline_ms: 100,
    }
}

fn browser_tools(manifest: &Value) -> Vec<&str> {
    manifest["provides"]
        .as_array()
        .expect("manifest provides is an array")
        .iter()
        .find(|role| role["role"] == "tool_provider")
        .expect("manifest has a tool provider")["tools"]
        .as_array()
        .expect("tool provider tools is an array")
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .filter(|name| name.starts_with("browser."))
        .collect()
}

#[test]
fn available_browser_surface_advertises_tools_without_refusal_disclosure() {
    let manifest = serialize_manifest_with_browser_configuration(
        "cerebellum",
        &BrowserSurface::Available(browser_surface_config()),
    );

    assert!(browser_tools(&manifest).contains(&"browser.navigate"));
    assert!(manifest.get("browser_surface_refused").is_none());
}

#[test]
fn not_configured_browser_surface_hides_tools_without_refusal_disclosure() {
    let manifest =
        serialize_manifest_with_browser_configuration("cerebellum", &BrowserSurface::NotConfigured);

    assert!(browser_tools(&manifest).is_empty());
    assert!(manifest.get("browser_surface_refused").is_none());
}

#[test]
fn parse_refused_browser_surface_hides_tools_and_discloses_parse_reason() {
    let manifest = serialize_manifest_with_browser_configuration(
        "cerebellum",
        &BrowserSurface::Refused(BrowserConfigError {
            field: "browser".to_string(),
            reason: browser_config::BrowserConfigReason::Malformed("unexpected token".to_string()),
        }),
    );

    assert!(browser_tools(&manifest).is_empty());
    assert_eq!(
        manifest["browser_surface_refused"],
        json!({
            "field": "browser",
            "reason_code": "malformed",
            "detail": "unexpected token",
        })
    );
}

#[test]
fn probe_refused_browser_surface_hides_tools_and_discloses_probe_reason() {
    let manifest = serialize_manifest_with_browser_configuration(
        "cerebellum",
        &BrowserSurface::Refused(BrowserConfigError {
            field: "browser.expected_identity".to_string(),
            reason: browser_config::BrowserConfigReason::ExecutableProbeFailed(
                "process exited 1".to_string(),
            ),
        }),
    );

    assert!(browser_tools(&manifest).is_empty());
    assert_eq!(
        manifest["browser_surface_refused"],
        json!({
            "field": "browser.expected_identity",
            "reason_code": "executable_probe_failed",
            "detail": "process exited 1",
        })
    );
}

use super::*;
use cerebellum_computer::platform::TargetResolution;
use subc_protocol::Principal;

/// A resolver that answers without consulting the machine.
///
/// The real one reads the window server, which makes a test of frame
/// ROUTING depend on which applications happen to be running and on a call
/// that takes seconds. What is under test here is where a request is sent,
/// so the answer it eventually gets should be a fixture rather than a
/// property of the desk it runs on.
struct NothingRunning;

#[cfg(target_os = "macos")]
struct OneRunning;

#[cfg(target_os = "macos")]
impl management::TargetResolver for OneRunning {
    fn resolve(&self, bundle_identity: &str) -> TargetResolution {
        TargetResolution::Resolved(cerebellum_computer::platform::ProcessGrant {
            pid: 4242,
            bundle_identity: bundle_identity.to_string(),
            process_generation_evidence: "test-generation".to_string(),
        })
    }

    fn app_code(
        &self,
        _grant: &cerebellum_computer::platform::ProcessGrant,
    ) -> Arc<dyn computer_grants::AppCode> {
        Arc::new(computer_grants::SignedByFixtureTeam)
    }
}

impl management::TargetResolver for NothingRunning {
    fn resolve(&self, _bundle_identity: &str) -> TargetResolution {
        TargetResolution::NotRunning
    }
}

/// A management plane for frame-level tests, resolving nothing.
fn test_management_plane() -> Arc<ManagementPlane> {
    Arc::new(ManagementPlane::new(Arc::new(NothingRunning)))
}

/// Minting through the management wire creates authority on the browser
/// plane built by the production constructor.
///
/// This is intentionally not a configured-grant fixture: the only authority
/// the navigation may use is the answer delivered to the elicitation request.
#[tokio::test]
async fn an_elicited_browser_grant_admits_wire_navigation() {
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::default()),
        Some(BrowserConfig {
            executable_path: None,
            expected_identity: None,
            launch_handshake_deadline_ms: 100,
            termination_grace_period_ms: 100,
            browser_idle_timeout_ms: 30_000,
            browser_exit_observation_deadline_ms: 100,
            navigation_settle_deadline_ms: 100,
        }),
        JournalPersistence::Isolated,
    );
    planes.management = Arc::new(
        ManagementPlane::new(Arc::new(management::PlatformResolver::new())).with_agent_grants(
            Arc::new(agent_grants::AgentGrants::in_memory(Some(
                "machine-test".into(),
            ))),
        ),
    );
    planes.browser = Arc::new(
        Arc::try_unwrap(planes.browser)
            .ok()
            .unwrap()
            .with_shared_grants(planes.management.browser_grants()),
    );
    let identity = bind_identity_for_test();
    let admission = json!({
        "agentProjectId": "test-project",
        "sessionKind": "primary",
        "effectiveCapabilityScope": ["*"],
    });
    planes.routes.insert(
        4,
        1,
        AcceptedBindFacts::from_bind(
            &identity,
            session_caller_principal_for_test(),
            Some(&admission),
            Some(&["elicitation".to_string()]),
            &subc_protocol::RouteTarget::ManagementSurface {
                module_id: "cerebellum".to_string(),
            },
        ),
    );
    planes.routes.insert(
        9,
        3,
        AcceptedBindFacts::from_bind(
            &identity,
            session_caller_principal_for_test(),
            Some(&admission),
            None,
            &subc_protocol::RouteTarget::ToolProvider {
                module_id: "cerebellum".to_string(),
            },
        ),
    );

    let planes = computer_grants::tests::CardService::install(planes, 4, 1);
    let tool_facts = planes.routes.get(9, 3).unwrap();
    planes.routes.insert(
        9,
        3,
        tool_facts.with_scope(planes.routes.get(4, 1).unwrap().scope),
    );
    let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
    let opening = Frame::build_with_version(
        subc_protocol::PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        4,
        1,
        71,
        serde_json::to_vec(&json!({
            "method": management::OPEN_GRANT,
            "params": {
                "origins": ["https://requested.example"],
                "hazards": [
                    "credential_form_submit",
                    "unverified_form_contents"
                ]
            }
        }))
        .unwrap(),
    )
    .unwrap();
    handle_frame(opening, &writer_tx, &planes)
        .await
        .expect("the grant request enters the production frame dispatcher");

    let frame = next_frame(&mut writer_rx).await;
    assert_ne!(frame.header.ty, FrameType::Request);
    let pending: Value = serde_json::from_slice(&frame.body).unwrap();
    assert_eq!(pending["outcome"], "consent_pending", "{pending}");
    let question_frame = planes.consent_test.as_ref().unwrap().card(4, 1).await;
    let question: Value = serde_json::from_slice(&question_frame.body).unwrap();
    assert_eq!(
        question["params"]["scope"]["origins"],
        json!(["https://requested.example"])
    );
    assert_eq!(
        question["params"]["scope"]["hazards"],
        json!(["credential_form_submit", "unverified_form_contents"])
    );
    // A disclosed hazard raises the ceiling to tier 4 (mutate_durable).
    // The open_grant call replies consent_pending without waiting for the
    // answer, so the card is not an interrupting alert.
    assert_eq!(question["params"]["scope"]["tier"], 4);
    assert_eq!(question["params"]["urgency"], "normal");
    // The person must be told, in words they can act on, what the grant
    // unlocks: each disclosed hazard names the kind of form it allows.
    let message = json!([question["params"]["prompt"], question["params"]["facts"]]).to_string();
    for disclosed in [
        "requested.example",
        // A disclosed hazard mints the durable tier, so the question must
        // state that tier's whole reach, not only the form kinds.
        "It can also follow links that lead to other sites",
        "It can also submit sign-in forms and forms whose purpose it couldn't check",
        "It can't submit payment forms",
    ] {
        assert!(
            message.contains(disclosed),
            "question omitted {disclosed}: {question}"
        );
    }
    // Legacy peers still receive the original deadline; capable peers
    // omit it when the card is raised.
    assert_eq!(question["params"]["expires_in_ms"], json!(1_800_000));

    assert!(planes.consent_test.as_ref().unwrap().answer(
        question_frame.header.corr,
        cingulate_client::ScriptedAnswer::Answered(json!({"decision":"allow_30m"}))
    ));
    assert_eq!(planes.browser.grant_count_for_test().await, 0);
    computer_grants::tests::drain_call(&planes, 4, 1).await;
    assert_eq!(
        planes
            .management
            .agent_grants()
            .live_rows(None, planes.management.agent_grants().now_ms())
            .unwrap()
            .len(),
        1
    );

    let navigation = Frame::build_with_version(
        subc_protocol::PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        9,
        3,
        72,
        serde_json::to_vec(&json!({
            "name": "browser.navigate",
            "arguments": {
                "url": "https://requested.example/path",
                "intent": "confirm the elicited authority reaches dispatch",
                "wait": "none",
                "severity": {"tier": 1, "credential": false, "financial": false}
            }
        }))
        .unwrap(),
    )
    .unwrap();
    handle_route_request(navigation, &writer_tx, &planes)
        .await
        .expect("the navigation reaches the browser wire handler");
    let navigated: Value =
        serde_json::from_slice(&writer_rx.recv().await.expect("navigation response").body).unwrap();
    assert_ne!(navigated["outcome"], "authorization_denied", "{navigated}");
    assert_eq!(navigated["outcome"], "no_session", "{navigated}");
}

mod would_ask_tests {
    use super::*;
    use crate::computer_grants::{
        AlwaysGrantRecord, ComputerGrants, GrantStorage, GrantStoreState, InMemoryGrantStorage,
        GRANT_STORE_VERSION,
    };

    fn planes() -> Planes {
        let mut planes = open_grant_planes();
        let storage = Arc::new(InMemoryGrantStorage::new());
        storage
            .save(&GrantStoreState {
                version: GRANT_STORE_VERSION,
                records: vec![AlwaysGrantRecord {
                    agent_project_id: "owner".to_string(),
                    bundle_identity: "com.example.Always".to_string(),
                    team_id: Some("TEAM".to_string()),
                    designated_requirement: Some("test requirement".to_string()),
                    machine_uuid: "machine".to_string(),
                    created_at_ms: 1,
                }],
            })
            .unwrap();
        planes.management = Arc::new(ManagementPlane::with_computer_grants(
            Arc::new(management::PlatformResolver::new()),
            Arc::new(ComputerGrants::open(storage, Some("machine".to_string()))),
        ));
        planes
    }

    async fn query(planes: &Planes, params: Value) -> Value {
        let (tx, mut rx) = mpsc::channel(8);
        let frame = Frame::build_with_version(
            subc_protocol::PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            4,
            1,
            500,
            serde_json::to_vec(&json!({"method":management::WOULD_ASK,"params":params})).unwrap(),
        )
        .unwrap();
        handle_frame(frame, &tx, planes).await.unwrap();
        let reply = next_frame(&mut rx).await;
        assert_ne!(reply.header.ty, FrameType::Request, "query raised a card");
        assert_no_card_raised(planes);
        assert!(rx.try_recv().is_err(), "unexpected extra frame");
        serde_json::from_slice(&reply.body).unwrap()
    }

    #[tokio::test]
    async fn standing_only_and_count_only_audit() {
        let planes = planes();
        planes
            .management
            .computer_grants()
            .seed_conversation_app_for_test(
                &planes.routes.get(4, 1).unwrap().identity.conversation_key,
                "com.example.Session",
            );
        let reply = query(
            &planes,
            json!({"flow_id":"flow:test","agent_id":"owner","items":[
                {"tool":"computer_use","target":"com.example.Always","level":4},
                {"tool":"computer_use","target":"com.example.Missing"},
                {"tool":"computer_use","target":"com.example.Session"}
            ]}),
        )
        .await;
        assert_eq!(
            reply,
            json!({"items":[
                {"tool":"computer_use","target":"com.example.Always","verdict":"yes","reason":"standing_grant"},
                {"tool":"computer_use","target":"com.example.Missing","verdict":"would_ask","reason":"no_standing_grant"},
                {"tool":"computer_use","target":"com.example.Session","verdict":"would_ask","reason":"no_standing_grant"}
            ]})
        );
        let export = planes.browser.journal_export_for_test().await;
        let entries: Vec<journal::JournalEntry> = export
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].identity.principal, "reserved:prefrontal");
        assert_eq!(
            entries[0].detail,
            Some(
                json!({"event":"grants.would_ask","caller":{"agent_id":"owner","flow_id":"flow:test"},"counts":{"item_count":3,"yes":1,"no":0,"would_ask":2}})
            )
        );
        assert!(!export.contains("com.example"));
        let other = query(&planes, json!({"flow_id":"flow:test","agent_id":"other","items":[{"tool":"computer_use","target":"com.example.Always"}]})).await;
        assert_eq!(other["items"][0]["verdict"], "would_ask");
    }

    /// Planes whose management plane holds a durable-shaped standing browser
    /// store (a machine identity, so rows can be recorded), with one row
    /// for `owner` on `https://example.com` up to `max_level`.
    fn planes_with_standing_origin_row(max_level: u8) -> Planes {
        use crate::browser_standing_grants::{
            InMemoryStandingGrantStorage, StandingBrowserGrants, StandingSubject,
        };
        let mut planes = open_grant_planes();
        let standing = Arc::new(StandingBrowserGrants::open(
            Arc::new(InMemoryStandingGrantStorage::new()),
            Some("machine".to_string()),
        ));
        standing
            .record(
                "owner",
                StandingSubject::Origin("https://example.com".to_string()),
                max_level,
                Vec::new(),
                None,
                "el_test",
            )
            .unwrap();
        planes.management = Arc::new(
            ManagementPlane::with_computer_grants(
                Arc::new(management::PlatformResolver::new()),
                Arc::new(ComputerGrants::open(
                    Arc::new(InMemoryGrantStorage::new()),
                    Some("machine".to_string()),
                )),
            )
            .with_standing_browser_grants(standing),
        );
        planes
    }

    #[tokio::test]
    async fn browser_without_a_standing_row_uses_public_baseline() {
        let reply = query(&planes(), json!({"flow_id":"flow:test","agent_id":"owner","items":[{"tool":"browser_use","target":"https://example.com","level":1}]})).await;
        assert_eq!(reply["items"][0]["verdict"], "yes");
        assert_eq!(reply["items"][0]["reason"], "public_web_baseline");
    }

    /// Public reads use the baseline across agents and origins; a requested
    /// tier above the baseline still needs a sufficient standing site grant.
    #[tokio::test]
    async fn browser_answers_from_standing_site_grants() {
        let planes = planes_with_standing_origin_row(2);
        let reply = query(
            &planes,
            json!({"flow_id":"flow:test","agent_id":"owner","items":[
                {"tool":"browser_use","target":"https://example.com","level":2},
                {"tool":"browser_use","target":"https://example.com"},
                {"tool":"browser_use","target":"https://example.com","level":3},
                {"tool":"browser_use","target":"https://example.org","level":1}
            ]}),
        )
        .await;
        assert_eq!(
            reply,
            json!({"items":[
                {"tool":"browser_use","target":"https://example.com","verdict":"yes","reason":"standing_grant"},
                {"tool":"browser_use","target":"https://example.com","verdict":"yes","reason":"public_web_baseline"},
                {"tool":"browser_use","target":"https://example.com","verdict":"would_ask","reason":"level_above_grant"},
                {"tool":"browser_use","target":"https://example.org","verdict":"yes","reason":"public_web_baseline"}
            ]})
        );
        let other = query(&planes, json!({"flow_id":"flow:test","agent_id":"other","items":[{"tool":"browser_use","target":"https://example.com","level":1}]})).await;
        assert_eq!(other["items"][0]["reason"], "public_web_baseline");
    }

    #[tokio::test]
    async fn inputs_are_closed_and_targets_are_validated() {
        let planes = planes();
        for target in [
            json!("null"),
            Value::Null,
            json!("https://example.com/path"),
            json!(""),
        ] {
            let reply = query(&planes, json!({"flow_id":"flow:test","agent_id":"owner","items":[{"tool":"browser_use","target":target}]})).await;
            assert_eq!(reply["items"][0]["verdict"], "no", "{reply}");
            assert_eq!(reply["items"][0]["reason"], "invalid_target");
        }
        for (params, field) in [
            (
                json!({"flow_id":"flow:test","agent_id":"owner","items":[],"extra":true}),
                "extra",
            ),
            (
                json!({"flow_id":"flow:test","agent_id":"owner","items":[{"tool":"computer_use","target":"com.example.App","extra":1}]}),
                "items[0].extra",
            ),
            (
                json!({"flow_id":"flow:test","agent_id":"owner","items":[]}),
                "items",
            ),
            (
                json!({"flow_id":"flow:test","agent_id":"owner","items":vec![json!({"tool":"computer_use","target":"com.example.App"});65]}),
                "items",
            ),
            (
                json!({"flow_id":"flow:test","agent_id":"owner","items":[{"tool":"computer_use","target":"com.example.App","level":5}]}),
                "items[0].level",
            ),
            (
                json!({"flow_id":"flow:test","agent_id":"owner","items":[{"tool":"other","target":"com.example.App"}]}),
                "items[0].tool",
            ),
        ] {
            let reply = query(&planes, params).await;
            assert_eq!(reply["outcome"], "invalid_request", "{reply}");
            assert_eq!(reply["detail"]["field"], field, "{reply}");
        }
    }

    #[tokio::test]
    async fn flow_identity_is_required_bounded_and_audit_only() {
        let planes = planes();
        for flow in [
            Value::Null,
            json!(""),
            json!("has space"),
            json!("line\nfeed"),
            json!("é"),
            json!("a".repeat(257)),
        ] {
            let reply = query(&planes, json!({"agent_id":"owner","flow_id":flow,"items":[{"tool":"computer_use","target":"com.example.Always"}]})).await;
            assert_eq!(reply["outcome"], "invalid_request", "{reply}");
            assert_eq!(reply["detail"]["field"], "flow_id", "{reply}");
        }
        let missing = query(&planes, json!({"agent_id":"owner","items":[{"tool":"computer_use","target":"com.example.Always"}]})).await;
        assert_eq!(missing["detail"]["field"], "flow_id");
        for flow in ["x".to_string(), "~".repeat(256)] {
            let reply = query(&planes, json!({"agent_id":"owner","flow_id":flow,"items":[{"tool":"computer_use","target":"com.example.Always"}]})).await;
            assert_eq!(reply["items"][0]["verdict"], "yes", "{reply}");
        }
    }

    #[test]
    fn result_schema_is_closed_and_withheld() {
        let planes = planes();
        for item in [
            json!({"tool":"computer_use","target":"com.example.App","verdict":"maybe","reason":"standing_grant"}),
            json!({"tool":"computer_use","target":"com.example.App","verdict":"yes","reason":"unknown"}),
            json!({"tool":"computer_use","target":"com.example.App","verdict":"yes","reason":"standing_grant","extra":true}),
        ] {
            assert!(planes
                .browser
                .finish_reply(management::WOULD_ASK, json!({"items":[item]}))
                .is_err());
        }
        assert!(!browser::tool_definitions()
            .iter()
            .any(|(name, _, _)| *name == management::WOULD_ASK));
    }

    #[tokio::test]
    async fn only_prefrontal_core_is_admitted() {
        for principal in [
            Some(subc_protocol::Principal::Direct),
            Some(subc_protocol::Principal::Reserved {
                module_id: "aft".to_string(),
            }),
            Some(subc_protocol::Principal::Reserved {
                module_id: "alfonso-core".to_string(),
            }),
        ] {
            let planes = planes();
            planes.routes.insert(
                4,
                1,
                AcceptedBindFacts::from_bind(
                    &bind_identity_for_test(),
                    principal,
                    None,
                    None,
                    &subc_protocol::RouteTarget::ManagementSurface {
                        module_id: "cerebellum".to_string(),
                    },
                ),
            );
            let reply = query(&planes, json!({"flow_id":"flow:test","agent_id":"owner","items":[{"tool":"computer_use","target":"com.example.Always"}]})).await;
            assert_eq!(reply["code"], "principal_denied", "{reply}");
            assert!(planes.browser.journal_export_for_test().await.is_empty());
        }
    }
}

/// Planes with an admitted agent-session management route and an answerable
/// consent-service fixture (channel 4, epoch 1).
fn open_grant_planes() -> Planes {
    let planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::default()),
        None,
        JournalPersistence::Isolated,
    );
    planes.routes.insert(
        4,
        1,
        AcceptedBindFacts::from_bind(
            &bind_identity_for_test(),
            session_caller_principal_for_test(),
            Some(&json!({
                "agentProjectId": "test-project",
                "sessionKind": "primary",
                "effectiveCapabilityScope": ["*"],
            })),
            Some(&["elicitation".to_string()]),
            &subc_protocol::RouteTarget::ManagementSurface {
                module_id: "cerebellum".to_string(),
            },
        ),
    );
    computer_grants::tests::CardService::install(planes, 4, 1)
}

fn open_grant_frame(corr: u64) -> Frame {
    Frame::build_with_version(
        subc_protocol::PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        4,
        1,
        corr,
        serde_json::to_vec(&json!({
            "method": management::OPEN_GRANT,
            "params": {"origins": ["https://requested.example"], "hazards": []}
        }))
        .unwrap(),
    )
    .unwrap()
}

/// One `browser.open_grant` through the production frame dispatcher: the
/// caller's immediate reply, and a synthetic inspection of the question
/// received by the consent service.
async fn open_grant_over_wire(
    planes: &Planes,
    writer: &mpsc::Sender<Frame>,
    rx: &mut mpsc::Receiver<Frame>,
    corr: u64,
) -> (Value, Frame) {
    handle_frame(open_grant_frame(corr), writer, planes)
        .await
        .unwrap();
    let frame = next_frame(rx).await;
    assert_ne!(frame.header.ty, FrameType::Request);
    let reply = serde_json::from_slice(&frame.body).unwrap();
    let question = planes.consent_test.as_ref().unwrap().card(4, 1).await;
    assert!(rx.try_recv().is_err(), "no reverse-lane question");
    (reply, question)
}

/// Script answers or expiry at the service, then apply them on a later call.
/// Refusals (`not_put_to_anyone`, `refused`, `undeliverable`) are not settled
/// feed records, so this helper updates their next-request notes directly.
/// The browser_consent tests send those refusals as RPC errors instead.
async fn end_question(
    planes: &Planes,
    writer: &mpsc::Sender<Frame>,
    question: &Frame,
    ending: &str,
) {
    let outcome = match ending {
        "no_answer" => cingulate_client::ScriptedAnswer::NoAnswer,
        "not_put_to_anyone" | "refused" => cingulate_client::ScriptedAnswer::NotPutToAnyone,
        "undeliverable" => cingulate_client::ScriptedAnswer::Undeliverable,
        _ => cingulate_client::ScriptedAnswer::Answered(json!({"decision":ending})),
    };
    assert!(planes
        .consent_test
        .as_ref()
        .unwrap()
        .answer(question.header.corr, outcome));
    if matches!(ending, "not_put_to_anyone" | "refused" | "undeliverable") {
        let ending = if ending == "undeliverable" {
            cingulate_client::desk::Ending::DeliveryFailed
        } else {
            cingulate_client::desk::Ending::NotPutToAnyone
        };
        planes
            .management
            .settle_browser_grant_ending(
                &format!("el_test_{}", question.header.corr),
                Some(&ending),
            )
            .await;
        planes
            .consent
            .mark_applied(&format!("el_test_{}", question.header.corr))
            .unwrap();
    } else if planes.routes.get(4, 1).is_some()
        && !planes.draining.load(std::sync::atomic::Ordering::SeqCst)
    {
        computer_grants::tests::drain_call(planes, 4, 1).await;
    }
    let _ = writer;
}

#[tokio::test]
async fn drain_leaves_an_already_detached_browser_card_answerable() {
    let planes = open_grant_planes();
    let (tx, mut rx) = mpsc::channel(8);
    let (_, question) = open_grant_over_wire(&planes, &tx, &mut rx, 900).await;
    let draining = Frame::build(
        FrameType::Push,
        Flags::new(false, Priority::Interactive, false),
        0,
        0,
        0,
        serde_json::to_vec(&json!({"op":"module.draining","reason":"restart","deadline_ms":123}))
            .unwrap(),
    )
    .unwrap();
    handle_frame(draining, &tx, &planes).await.unwrap();
    assert!(rx.try_recv().is_err());
    assert!(planes.consent_test.as_ref().unwrap().answer(
        question.header.corr,
        cingulate_client::ScriptedAnswer::Answered(json!({"decision":"allow_30m"}))
    ));
    assert_eq!(planes.management.browser_grant_count().await, 0);
    assert!(planes
        .consent_test
        .as_ref()
        .unwrap()
        .calls()
        .iter()
        .all(|(method, _)| method != "consent.withdraw"));
}

#[tokio::test]
async fn scope_revocation_forgets_detached_browser_card_without_a_route() {
    let planes = open_grant_planes();
    let (tx, mut rx) = mpsc::channel(8);
    let (_, question) = open_grant_over_wire(&planes, &tx, &mut rx, 901).await;
    let conversation = planes.routes.get(4, 1).unwrap().identity.conversation_key;
    let count = planes.consent_test.as_ref().unwrap().calls().len();
    revoke_scope(&planes, &std::collections::BTreeSet::from([conversation])).await;
    assert!(rx.try_recv().is_err());
    assert!(planes
        .consent
        .raised(&format!("el_test_{}", question.header.corr))
        .is_none());
    assert_eq!(planes.consent_test.as_ref().unwrap().calls().len(), count);
    assert_eq!(planes.management.browser_grant_count().await, 0);
}

/// A bind at a higher epoch of the same session scope forgets the cards
/// the ended epoch raised, even after that epoch's route has closed, and
/// opens no route to Cingulate to do it.
#[tokio::test]
async fn an_advanced_epoch_bind_forgets_the_ended_sessions_cards_without_a_route() {
    let planes = open_grant_planes();
    let (tx, mut rx) = mpsc::channel(8);
    let (_, question) = open_grant_over_wire(&planes, &tx, &mut rx, 902).await;
    let id = format!("el_test_{}", question.header.corr);
    assert!(planes.consent.raised(&id).is_some());
    let old = planes.routes.get(4, 1).unwrap();
    let old_stamp = old.scope.clone().unwrap();
    // The epoch-1 route was bound through the epoch check and has since
    // closed, so no bound route names the ended session any more.
    planes
        .scopes
        .note_bind(&old_stamp, &old.identity.conversation_key);
    planes.routes.remove(4, 1);
    let count = planes.consent_test.as_ref().unwrap().calls().len();

    let mut stamp = old_stamp;
    stamp.scope_epoch = 2;
    let bind = ModuleControlRequest::RouteBind {
        role_versions: None,
        call_mode: None,
        route_channel: 5,
        epoch: 1,
        target: subc_protocol::RouteTarget::ManagementSurface {
            module_id: "cerebellum".into(),
        },
        identity: bind_identity_for_test(),
        principal: session_caller_principal_for_test(),
        consumer_capabilities: None,
        admission_facts: Some(json!({
            "agentProjectId": "test-project",
            "sessionKind": "primary",
            "effectiveCapabilityScope": ["*"],
        })),
        scope: Some(stamp),
    };
    let frame = Frame::build_with_version(
        subc_protocol::PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Passive, false),
        0,
        0,
        5,
        serde_json::to_vec(&bind).unwrap(),
    )
    .unwrap();
    assert!(handle_frame(frame, &tx, &planes).await.unwrap());
    let reply = tokio::time::timeout(HANG_GUARD, rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        reply.header.ty,
        FrameType::Response,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    assert!(
        planes.consent.raised(&id).is_none(),
        "the ended epoch's card is still in the registry"
    );
    assert_eq!(planes.consent_test.as_ref().unwrap().calls().len(), count);
    assert!(rx.try_recv().is_err());
}

async fn browser_grants_settled(planes: &Planes) {
    tokio::time::timeout(HANG_GUARD, async {
        while planes.management.browser_grant_pending_count().await != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the question settles");
}

/// A browser grant question settled by nobody being asked is named on the
/// next request for the same grant, and no other ending is, while none of
/// them grants anything.
///
/// The caller's pending reply says to retry once the request has been
/// answered. For a question nobody was shown that answer never comes, so
/// the next reply has to say so; silence from a person who was asked is not
/// reported this way, or the field would only repeat "not answered yet".
#[tokio::test]
async fn a_browser_grant_nobody_was_asked_is_named_on_the_next_request() {
    // The ending, and whether the next request reports it.
    let cases = [
        ("deny", false),
        ("no_answer", false),
        ("not_put_to_anyone", true),
        ("refused", true),
        ("undeliverable", false),
        ("some_future_word", false),
    ];
    for (ending, reported) in cases {
        let planes = open_grant_planes();
        let (writer, mut rx) = mpsc::channel::<Frame>(8);
        let (first, question) = open_grant_over_wire(&planes, &writer, &mut rx, 80).await;
        assert_eq!(first["outcome"], "consent_pending", "{first}");
        assert!(first.get("previous_request").is_none(), "{first}");
        end_question(&planes, &writer, &question, ending).await;
        let first_ask = Some(first["ask_id"].as_str().unwrap().to_string());
        browser_grants_settled(&planes).await;
        assert_eq!(
            planes.management.browser_grant_count().await,
            0,
            "{ending} granted something"
        );

        let (next, _) = open_grant_over_wire(&planes, &writer, &mut rx, 81).await;
        assert_eq!(next["outcome"], "consent_pending", "{ending}: {next}");
        if reported {
            let previous = &next["previous_request"];
            assert_eq!(previous["ask_id"], json!(first_ask), "{ending}: {next}");
            assert_eq!(previous["disposition"], "not_put_to_anyone", "{next}");
            let remedy = previous["remedy"].as_str().unwrap().to_lowercase();
            for loop_word in ["ask again", "retry", "wait"] {
                assert!(
                    !remedy.contains(loop_word),
                    "a question nobody was shown sends the caller round a loop: {remedy}"
                );
            }
        } else {
            assert!(
                next.get("previous_request").is_none(),
                "{ending} was reported as unreached: {next}"
            );
        }
    }
}

/// Every ending of a grant question a browser action is held open on maps
/// to its own decision word and remedy. The wire test drives each ending a
/// consumer can produce; a question that could not be sent also fails the
/// reply on the same closed writer, so its word is pinned here.
#[test]
fn each_in_call_grant_ending_has_its_own_decision_and_remedy() {
    let cases = [
        (
            cingulate_client::desk::Ending::Declined {
                choice_id: "deny".into(),
            },
            "declined",
        ),
        (cingulate_client::desk::Ending::NoAnswer, "no_answer"),
        (
            cingulate_client::desk::Ending::NotPutToAnyone,
            "not_put_to_anyone",
        ),
        (
            cingulate_client::desk::Ending::DeliveryFailed,
            "undeliverable",
        ),
        (
            cingulate_client::desk::Ending::Declined {
                choice_id: "some_future_word".into(),
            },
            "unrecognized_answer",
        ),
    ];
    let mut remedies = std::collections::BTreeSet::new();
    for (ending, decision) in cases {
        assert_eq!(in_call_grant_decision(&ending), decision);
        let remedy = in_call_grant_remedy(decision).expect("a remedy");
        assert!(remedies.insert(remedy), "{decision} shares a remedy");
        if decision == "not_put_to_anyone" {
            let remedy = remedy.to_lowercase();
            for loop_word in ["ask again", "retry", "wait"] {
                assert!(!remedy.contains(loop_word), "{remedy}");
            }
        }
    }
    // A question withdrawn before it ended keeps the refusal's remedy.
    for withdrawn in ["cancelled", "route_closed", "draining", "unavailable"] {
        assert_eq!(in_call_grant_remedy(withdrawn), None);
    }
}

/// Once a person is reached, the next `browser.open_grant` reply stops
/// carrying `previous_request` for an earlier question nobody was shown. A
/// question that could not be sent says nothing about whether a person is
/// reachable, so `previous_request` keeps naming the earlier one.
#[tokio::test]
async fn reaching_a_person_retires_the_earlier_unreached_browser_grant_report() {
    let planes = open_grant_planes();
    let (writer, mut rx) = mpsc::channel::<Frame>(8);
    let (first, question) = open_grant_over_wire(&planes, &writer, &mut rx, 90).await;
    end_question(&planes, &writer, &question, "refused").await;
    browser_grants_settled(&planes).await;

    let (closed, mut closed_rx) = mpsc::channel::<Frame>(8);
    closed_rx.close();
    let _ = handle_frame(open_grant_frame(91), &closed, &planes).await;
    browser_grants_settled(&planes).await;

    let (second, question) = open_grant_over_wire(&planes, &writer, &mut rx, 92).await;
    assert_eq!(
        second["previous_request"]["ask_id"], first["ask_id"],
        "an undeliverable question retired the report: {second}"
    );
    end_question(&planes, &writer, &question, "no_answer").await;
    browser_grants_settled(&planes).await;

    let (third, _) = open_grant_over_wire(&planes, &writer, &mut rx, 93).await;
    assert!(
        third.get("previous_request").is_none(),
        "a stale unreached report survived reaching a person: {third}"
    );
}

/// The refusal names the exact target fact absent from the human disclosure.
#[tokio::test]
async fn a_wire_built_plane_names_the_undisclosed_target_hazard() {
    let management = ManagementPlane::new(Arc::new(NothingRunning));
    let question = management
        .browser_grant_question_for_test(
            "conversation",
            vec!["https://login.example".to_string()],
            vec![crate::authorization::HazardClass::FinancialFormSubmit],
        )
        .await;
    management
        .settle_browser_grant(&question.ask_id, Some(&json!({"decision": "allow_30m"})))
        .await;
    let browser = browser_plane_with_shared_grants_for_test(management.browser_grants());
    let route = RouteIdentity {
        conversation_key: "conversation".to_string(),
        ..RouteIdentity::from_accepted_bind(
            &bind_identity_for_test(),
            &Some(Principal::Direct),
            Some(&json!({"agentProjectId": "test-project", "sessionKind": "primary"})),
        )
    };
    browser.open_context(route.clone()).await.unwrap();
    let submit = crate::classification::ElementClassificationInput::new(
        crate::classification::NodeIdentityInput::new("target", "frame", 42),
        crate::classification::TargetKind::Button,
    )
    .form_owner(crate::classification::NodeIdentityInput::new(
        "target", "frame", 7,
    ))
    .associated_control(
        crate::classification::AssociatedFormControlInput::new(
            crate::classification::NodeIdentityInput::new("target", "frame", 8),
        )
        .with_tokens(["current-password"]),
    );
    let classification = crate::classification::classify_click(
        &crate::classification::NonTypeClassificationInput::new(0, submit, "https://login.example"),
    )
    .unwrap();
    browser
        .same_document_url(
            &route,
            "https://login.example/page",
            crate::snapshot_store::SameDocumentChange::ReplaceState,
        )
        .await
        .unwrap();
    let retained = browser
        .retain_text_snapshot(
            &route,
            crate::snapshot_store::SnapshotKind::Ax,
            // A snapshot keeps only the refs its text names.
            &["e1", "e2"].map(|reference| crate::snapshot_store::AxRecord {
                depth: 0,
                role: "button".into(),
                name: String::new(),
                value: None,
                reference: Some(reference.into()),
            }),
            None,
            vec![
                crate::snapshot_store::RefRecord {
                    frame_document: None,
                    captured: crate::snapshot_store::SnapshotRef::new("e1", "button", "Sign in", 0)
                        .unwrap(),
                    frame_path: vec!["frame".to_string()],
                    backend_identity: Some(
                        crate::snapshot_store::BackendNodeIdentity::new("target", "frame", 42)
                            .unwrap(),
                    ),
                    raw_role: Some("button".to_string()),
                    raw_name: Some("Sign in".to_string()),
                    classification: Ok(Box::new(classification)),
                },
                crate::snapshot_store::RefRecord {
                    frame_document: None,
                    captured: crate::snapshot_store::SnapshotRef::new(
                        "e2", "button", "Continue", 0,
                    )
                    .unwrap(),
                    frame_path: vec!["frame".to_string()],
                    backend_identity: Some(
                        crate::snapshot_store::BackendNodeIdentity::new("target", "frame", 43)
                            .unwrap(),
                    ),
                    raw_role: Some("button".to_string()),
                    raw_name: Some("Continue".to_string()),
                    classification: Err(
                        crate::classification::ClassificationUnavailable::NotCaptured,
                    ),
                },
            ],
            4096,
            None,
        )
        .await
        .unwrap();
    let result = browser
        .dispatch(
            &route,
            crate::browser::BrowserCapability::Click,
            &json!({
                "ref": "e1",
                "snapshot_id": retained["snapshot_id"],
                "intent": "sign in",
                "severity": {"tier": 4, "credential": true, "financial": false}
            }),
        )
        .await;

    assert_eq!(result["outcome"], "hazard_not_disclosed", "{result}");
    assert_eq!(
        result["detail"]["missing_hazard"], "credential_form_submit",
        "{result}"
    );
    assert_eq!(
        result["remedy"], "call open_grant with the arguments in detail.grant_request, then retry",
        "{result}"
    );
    assert_eq!(
        result["detail"]["grant_request"]["hazards"],
        json!(["credential_form_submit"]),
        "{result}"
    );

    let unknown = browser
        .dispatch(
            &route,
            crate::browser::BrowserCapability::Click,
            &json!({
                "ref": "e2",
                "snapshot_id": retained["snapshot_id"],
                "intent": "continue",
                "severity": {"tier": 4, "credential": true, "financial": false}
            }),
        )
        .await;
    assert_eq!(
        unknown["outcome"], "classification_unavailable",
        "{unknown}"
    );
    assert_eq!(
        unknown["detail"]["classification_unavailable"],
        "not_captured"
    );
    assert!(unknown["detail"].get("required").is_none());
    assert!(unknown["detail"].get("grant_request").is_none());
    // No classification was captured, so the next step must capture it;
    // choosing another ref cannot repair missing document facts.
    let remedy = unknown["remedy"].as_str().unwrap();
    assert!(remedy.contains("capture target classification"));
    assert!(!remedy.contains("enclosing element"));
}

/// A response or error frame on a route channel is dropped without
/// disturbing the loop.
///
/// This module sends no requests on a route channel (permission cards go
/// to Cingulate, the consent module, over a route of their own), so such a
/// frame answers nothing here. It must neither be acted on nor take the
/// connection down, and nothing is written back.
#[tokio::test]
async fn an_unsolicited_answer_is_dropped_without_closing_the_route() {
    let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);

    let planes = Planes {
        private_content: Arc::new(private_content::PrivateContent::in_memory()),
        agent_data: Arc::new(agent_data::Participant::in_memory()),
        image_handles: Arc::new(image_handles::ImageHandles::default()),
        signed_in: Arc::new(browser_signed_in::SignedInDomains::default()),
        cancellations: RequestCancellations::default(),
        operator_confirm: Arc::default(),
        run_calls: codemode::RunCalls::default(),
        browser_resumes: Arc::default(),
        browser_queue: Arc::new(call_queue::ConversationQueue::default()),
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        computer_admitted: test_admitted_computer_capabilities(),
        health: Arc::new(HealthState::default()),
        routes: Arc::new(RouteBindings::new()),
        browser: Arc::new(BrowserPlane::new()),
        browser_config: None,
        runtime_browser: None,
        sessions: browser_session::BrowserSessions::default(),
        user_browser: user_browser_bridge::UserBrowserBridge::new(),
        lease_clock: Arc::new(cerebellum_core::clock::SystemClock::new()),
        launch_service: None,
        management: test_management_plane(),
        consent: Arc::new(cingulate_client::desk::ConsentDesk::new(Arc::new(
            consent_drain::UnconfiguredCingulate,
        ))),
        consent_drain: Arc::new(consent_drain::ConsentDrain::default()),
        user_browser_cards: Arc::default(),
        #[cfg(test)]
        consent_test: None,
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        computer: Err(computer_capability::ComputerPlaneUnavailable::CaptureCustody),
        draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        drain_signal: Arc::new(tokio::sync::watch::channel(false).0),
        drain_notice: Arc::new(std::sync::OnceLock::new()),
        route_test_handler: None,
        cursor_for_test: None,
        #[cfg(all(test, target_os = "macos"))]
        computer_for_test: None,
        capture: login_capture::test_support::fixture().module,
        calls: Arc::new(journal::call_records::CallRecords::in_memory()),
        call_record_workers: Arc::new(CallRecordWorkers::default()),
        egress_deadlines: Arc::new(ConnectionDeadlines::default()),
        scopes: Arc::new(scope_watch::ScopeRevocation::default()),
    };
    for ty in [FrameType::Response, FrameType::Error] {
        let answer = Frame::build(
            ty,
            Flags::new(false, Priority::Interactive, false),
            4,
            1,
            9_999,
            br#"{"decision":"allow"}"#.to_vec(),
        )
        .unwrap();
        let keep_going = handle_frame(answer, &writer_tx, &planes)
            .await
            .expect("an unsolicited answer is handled");
        assert!(keep_going, "an unsolicited {ty:?} closed the connection");
        assert!(
            writer_rx.try_recv().is_err(),
            "an unsolicited {ty:?} was answered"
        );
    }
}

/// A management route is served by the management surface, not the tool one.
///
/// The two take different envelopes, so a management request reaching the
/// tool path is rejected as a malformed tool call: the caller is told its
/// request was invalid when the module simply sent it to the wrong place.
///
/// Driven through the real entry point, because a test calling the
/// management handler directly would pass however the routing behaved.
#[tokio::test]
async fn a_management_route_is_served_by_the_management_surface() {
    let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
    let planes = management_bound_planes(4, 1);

    let request = serde_json::json!({
        "method": management::OPEN_TARGET,
        "params": {
            "bundle_identity": "com.example.Nothing",
        },
    });
    let frame = Frame::build_with_version(
        subc_protocol::PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        4,
        1,
        77,
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();

    handle_route_request(frame, &writer_tx, &planes)
        .await
        .expect("a management request is served");

    let response = writer_rx.recv().await.expect("a response frame");
    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    // The operation ran: it resolved the name and found nothing running.
    // Served by the tool path this would be a rejected envelope instead.
    assert_eq!(
        body["outcome"], "not_running",
        "a management request was not served by the management surface: {body}"
    );
}

#[tokio::test]
async fn a_management_route_without_an_agent_session_gets_no_browser_grant_question() {
    let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
    let planes = management_bound_planes(4, 1);
    let request = serde_json::json!({
        "method": management::OPEN_GRANT,
        "params": {
            "origins": ["https://example.test"],
            "hazards": ["unverified_form_contents"],
        },
    });
    let frame = Frame::build_with_version(
        subc_protocol::PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        4,
        1,
        79,
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();

    handle_route_request(frame, &writer_tx, &planes)
        .await
        .expect("the grant operation is served");
    let response = writer_rx.recv().await.expect("an immediate response");
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["outcome"], "consent_unavailable", "{body}");
    assert_eq!(planes.management.browser_grant_count().await, 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), writer_rx.recv())
            .await
            .is_err(),
        "a consumer that did not declare elicitation received a question"
    );
}

#[tokio::test]
async fn browser_present_and_import_login_reject_opaque_origin_before_side_effects() {
    for method in [management::PRESENT, management::IMPORT_LOGIN] {
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
        let planes = management_bound_planes(4, 1);
        let frame = Frame::build_with_version(
            subc_protocol::PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            4,
            1,
            105,
            serde_json::to_vec(&json!({"method": method, "params": {"origin": "null"}})).unwrap(),
        )
        .unwrap();

        handle_route_request(frame, &writer_tx, &planes)
            .await
            .expect("an opaque origin receives a response");
        let response = writer_rx.recv().await.expect("an invalid-request response");
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["outcome"], "invalid_request", "{method}: {body}");
        assert_eq!(body["detail"]["field"], "origin", "{method}: {body}");
        assert_eq!(
            body["detail"]["reason_code"], "invalid_origin",
            "{method}: {body}"
        );
        assert!(
            writer_rx.try_recv().is_err(),
            "{method} sent an elicitation frame"
        );
        assert!(
            planes.browser.operation_log().await.is_empty(),
            "{method} operated the browser"
        );
    }
}

#[tokio::test]
async fn browser_import_login_params_are_exactly_closed() {
    let cases = [
        (
            json!({"method": management::IMPORT_LOGIN, "params": {"origin": "https://x.com", "extra": true}}),
            "extra",
            "unknown_field",
        ),
        (
            json!({"method": management::IMPORT_LOGIN, "params": {}}),
            "origin",
            "missing_field",
        ),
        (
            json!({"method": management::IMPORT_LOGIN, "params": {"origin": 7}}),
            "origin",
            "wrong_type",
        ),
        (
            json!({"method": management::IMPORT_LOGIN, "params": {"origin": "https://x.com/path"}}),
            "origin",
            "invalid_origin",
        ),
    ];

    for (correlation, (request, field, reason)) in cases.into_iter().enumerate() {
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
        let planes = management_bound_planes(4, 1);
        let frame = Frame::build_with_version(
            subc_protocol::PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            4,
            1,
            correlation as u64 + 100,
            serde_json::to_vec(&request).unwrap(),
        )
        .unwrap();
        handle_route_request(frame, &writer_tx, &planes)
            .await
            .expect("the import request is answered");
        let response = writer_rx.recv().await.expect("an invalid-request response");
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["outcome"], "invalid_request", "{body}");
        assert_eq!(body["detail"]["field"], field, "{body}");
        assert_eq!(body["detail"]["reason_code"], reason, "{body}");
    }
}

#[tokio::test]
async fn browser_import_login_refuses_without_an_agent_session() {
    let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
    let planes = management_bound_planes(4, 1);
    let request = json!({
        "method": management::IMPORT_LOGIN,
        "params": {"origin": "https://x.com"},
    });
    let frame = Frame::build_with_version(
        subc_protocol::PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        4,
        1,
        104,
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();

    handle_route_request(frame, &writer_tx, &planes)
        .await
        .expect("the import request is answered");
    let response = writer_rx.recv().await.expect("an immediate refusal");
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["outcome"], "consent_unavailable", "{body}");
    assert_eq!(body["detail"]["reason"], "no_agent_session", "{body}");
    assert_eq!(
        body["remedy"],
        "call from the agent session that needs the permission; it can raise the card",
        "{body}"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), writer_rx.recv())
            .await
            .is_err(),
        "an undeclared elicitation question was sent"
    );
}

/// Planes whose management route declares elicitation, with the capture
/// module running on the fixture's fakes and an in-memory journal.
pub(super) fn capture_planes(fixture: &login_capture::test_support::Fixture) -> Planes {
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::default()),
        None,
        JournalPersistence::Isolated,
    );
    planes.capture = Arc::clone(&fixture.module);
    planes.browser_config = Some(Planes::short_test_browser_config());
    let admission = json!({
        "agentProjectId": "test-project",
        "sessionKind": "primary",
        "effectiveCapabilityScope": ["*"],
        "browserControlOperations": ["browser.capture_login"],
    });
    planes.routes.insert(
        4,
        1,
        AcceptedBindFacts::from_bind(
            &bind_identity_for_test(),
            session_caller_principal_for_test(),
            Some(&admission),
            Some(&["elicitation".to_string()]),
            &subc_protocol::RouteTarget::ToolProvider {
                module_id: "cerebellum".to_string(),
            },
        ),
    );
    computer_grants::tests::CardService::install(planes, 4, 1)
}

pub(super) fn capture_request_frame(correlation: u64, params: Value) -> Frame {
    let mut arguments = params;
    arguments["action"] = json!("capture_login");
    Frame::build_with_version(
        subc_protocol::PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        4,
        1,
        correlation,
        serde_json::to_vec(&json!({
            "name": flat_tools::BROWSER_USE,
            "call_key": format!("pf:capture-{correlation}"),
            "arguments": arguments,
        }))
        .unwrap(),
    )
    .unwrap()
}

fn ollama_capture_params() -> Value {
    json!({
        "credential_domain": "ollama.com",
        "account": "work",
        "fetch_url": "https://ollama.com/settings",
        "login_url": "https://ollama.com/signin",
    })
}

async fn next_frame(rx: &mut mpsc::Receiver<Frame>) -> Frame {
    tokio::time::timeout(HANG_GUARD, rx.recv())
        .await
        .expect("the capture answers promptly")
        .expect("the writer stays open")
}

/// One test's Cingulate and consent registry: a scripted Cingulate and a
/// registry file of the test's own, so planes can be built again over the
/// same file and the same Cingulate, as a restarted module would be.
pub(super) struct ScriptedConsent {
    pub(super) script: Arc<cingulate_client::ScriptedCingulate>,
    dir: PathBuf,
}

impl ScriptedConsent {
    pub(super) fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let dir = std::env::temp_dir().join(format!(
            "scripted-consent-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self {
            script: cingulate_client::ScriptedCingulate::new().accept_execution_reports(),
            dir,
        }
    }

    pub(super) fn store(&self) -> cingulate_client::desk::FileRegistryStore {
        cingulate_client::desk::FileRegistryStore::new(self.dir.join("cingulate_raised.json"))
    }

    /// `planes` with their consent desk raising cards with the script and
    /// keeping its registry in the test's file, and the route at
    /// `channel` bound to an admitted agent session.
    pub(super) fn wire(&self, planes: Planes, channel: u16, epoch: u32) -> Planes {
        let planes =
            planes.with_cingulate(Arc::new(Arc::clone(&self.script)), Arc::new(self.store()));
        let facts = planes.routes.get(channel, epoch).unwrap();
        planes.routes.insert(
            channel,
            epoch,
            facts.with_scope(Some(computer_grants::tests::stamp("test-project"))),
        );
        planes
    }

    /// Planes running the fixture's capture module behind the production
    /// frame dispatcher, on the route at channel 4. Each call builds them
    /// anew over the same registry.
    fn planes(&self, fixture: &login_capture::test_support::Fixture) -> Planes {
        let mut planes = Planes::with_browser_config_journaling(
            Arc::new(HealthState::default()),
            None,
            JournalPersistence::Isolated,
        );
        planes.capture = Arc::clone(&fixture.module);
        planes.browser_config = Some(Planes::short_test_browser_config());
        let admission = json!({
            "agentProjectId": "test-project",
            "sessionKind": "primary",
            "effectiveCapabilityScope": ["*"],
            "browserControlOperations": ["browser.capture_login"],
        });
        planes.routes.insert(
            4,
            1,
            AcceptedBindFacts::from_bind(
                &bind_identity_for_test(),
                session_caller_principal_for_test(),
                Some(&admission),
                None,
                &subc_protocol::RouteTarget::ToolProvider {
                    module_id: "cerebellum".to_string(),
                },
            ),
        );
        self.wire(planes, 4, 1)
    }

    /// Cingulate raises the next card under `id`.
    pub(super) fn raises(&self, id: &str) -> &Self {
        self.script.then(
            cingulate_client::wire::CONSENT_REQUEST,
            cingulate_client::Reply::Result(json!({"elicitation_id": id})),
        );
        self
    }

    /// The person answers `choice` while the call holds card `id`.
    fn answered_in_call(&self, id: &str, choice: &str) -> &Self {
        self.script.then(
            cingulate_client::wire::CONSENT_AWAIT,
            cingulate_client::Reply::Result(
                json!({"elicitation_id": id, "state": "answered", "answered_choice_id": choice}),
            ),
        );
        self
    }

    /// Card `id` is still open when the call stops holding it, and is
    /// detached.
    pub(super) fn unanswered(&self, id: &str) -> &Self {
        self.script
            .then(
                cingulate_client::wire::CONSENT_AWAIT,
                cingulate_client::Reply::Result(json!({"elicitation_id": id, "state": "pending"})),
            )
            .then(
                cingulate_client::wire::CONSENT_DETACH,
                cingulate_client::Reply::Result(
                    json!({"elicitation_id": id, "state": "pending", "detached": true}),
                ),
            );
        self
    }

    /// The session's next call reads `records` from the answers feed and
    /// acknowledges them.
    pub(super) fn feed(&self, records: Value) -> &Self {
        self.script
            .then(
                cingulate_client::wire::CONSENT_ANSWERS,
                cingulate_client::Reply::Result(json!({"records": records, "cursor": 1})),
            )
            .then(
                cingulate_client::wire::CONSENT_ACK,
                cingulate_client::Reply::Result(json!({"cursor": 1})),
            );
        self
    }

    /// Cingulate takes a report of what became of approved card `id`.
    pub(super) fn takes_report(&self, id: &str) -> &Self {
        self.script.then(
            cingulate_client::wire::CONSENT_REPORT_EXECUTION,
            cingulate_client::Reply::Result(
                json!({"elicitation_id": id, "state": "answered", "answered_choice_id": "allow"}),
            ),
        );
        self
    }

    pub(super) fn methods(&self) -> Vec<String> {
        self.script.methods()
    }

    /// The cards raised so far, as `consent.request` params.
    pub(super) fn cards(&self) -> Vec<Value> {
        self.script
            .calls()
            .into_iter()
            .filter(|(method, _)| method == cingulate_client::wire::CONSENT_REQUEST)
            .map(|(_, params)| params)
            .collect()
    }
}

impl Drop for ScriptedConsent {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub(super) fn late_answer(id: &str, choice: &str) -> Value {
    json!([{"elicitation_id": id, "state": "answered", "answered_choice_id": choice}])
}

/// Consent uses Cingulate's card service, not the incoming request route;
/// that route receives only the initial reply, not the later settlement.
async fn capture_initial_reply(
    planes: &Planes,
    writer: &mpsc::Sender<Frame>,
    rx: &mut mpsc::Receiver<Frame>,
    corr: u64,
    params: Value,
) -> Value {
    handle_frame(capture_request_frame(corr, params), writer, planes)
        .await
        .unwrap();
    let frame = next_frame(rx).await;
    let body: Value = serde_json::from_slice(&frame.body).unwrap();
    assert_eq!(
        frame.header.ty,
        FrameType::Response,
        "a frame other than the reply reached the route: {body}"
    );
    assert_eq!(frame.header.corr, corr);
    body
}

async fn capture_reply(
    planes: &Planes,
    writer: &mpsc::Sender<Frame>,
    rx: &mut mpsc::Receiver<Frame>,
    corr: u64,
    params: Value,
) -> Value {
    let credential_id = params["credential_domain"]
        .as_str()
        .zip(params["account"].as_str())
        .map(|(domain, account)| format!("cookie:{domain}:{account}"));
    let captured_before = match credential_id.as_deref() {
        Some(id) => capture_audit_tests::captured_count(planes, id).await,
        None => 0,
    };
    let body = capture_initial_reply(planes, writer, rx, corr, params).await;
    if body["outcome"] == "capture_pending" {
        let late = capture_stored_late(planes, corr).await;
        // Consent tests need the finished deposit and disposal result,
        // not merely confirmation that the sign-in window was handed over.
        let result = late["result"].clone();
        if result["outcome"] == "captured" {
            // Late results intentionally publish before the asynchronous
            // audit write. Wait for this capture's new row, not a row left
            // by an earlier successful request for the same credential.
            capture_audit_tests::wait_for_new_capture(
                planes,
                credential_id
                    .as_deref()
                    .expect("a captured request names a credential"),
                captured_before,
            )
            .await;
        }
        result
    } else {
        body
    }
}

async fn capture_provider_op(planes: &Planes, channel: u16, name: &str, arguments: Value) -> Value {
    let mut arguments = arguments;
    if name == "late_results" {
        arguments["since"] = Value::Null;
    }
    let mut frame = capture_request_frame(90_000, ollama_capture_params());
    frame.header.channel = channel;
    frame.body = serde_json::to_vec(&json!({"name":name,"arguments":arguments})).unwrap();
    let (tx, mut rx) = mpsc::channel(8);
    handle_frame(frame, &tx, planes).await.unwrap();
    let reply = next_frame(&mut rx).await;
    assert_eq!(reply.header.ty, FrameType::Response);
    let reply: Value = serde_json::from_slice(&reply.body).unwrap();
    reply.get("structuredContent").cloned().unwrap_or(reply)
}

pub(super) async fn capture_late(planes: &Planes, corr: u64) -> Value {
    capture_stored_late(planes, corr).await;
    let reply = capture_provider_op(planes, 4, "late_results", json!({})).await;
    reply["entries"]
        .as_array()
        .expect("late-results serves entries")
        .iter()
        .find(|entry| entry["call_key"] == format!("pf:capture-{corr}"))
        .expect("the provider serves the stored settlement")
        .clone()
}

async fn capture_stored_late(planes: &Planes, corr: u64) -> Value {
    let principal =
        journal::call_records::principal_label(planes.routes.get(4, 1).unwrap().principal.as_ref());
    // Wait on CallRecords first: a late_results request also reads the
    // consent answer feed, which must not race the scripted Cingulate
    // report that a consumed approval was executed.
    tokio::time::timeout(HANG_GUARD, async {
        loop {
            let reply = planes
                .calls
                .late_results(
                    &principal,
                    &cortexkit_role_tool_provider::late_results::LateResultsRequest::new(),
                    wall_clock_ms(),
                )
                .unwrap();
            let reply = serde_json::to_value(reply).unwrap();
            if let Some(entry) = reply["entries"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["call_key"] == format!("pf:capture-{corr}"))
            {
                break entry.clone();
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the handed-over capture settles")
}

async fn interrupt_capture(planes: &Planes, corr: u64) {
    planes
        .draining
        .store(true, std::sync::atomic::Ordering::Release);
    let principal =
        journal::call_records::principal_label(planes.routes.get(4, 1).unwrap().principal.as_ref());
    tokio::time::timeout(HANG_GUARD, async {
        loop {
            let reply = planes
                .calls
                .late_results(
                    &principal,
                    &cortexkit_role_tool_provider::late_results::LateResultsRequest::new(),
                    wall_clock_ms(),
                )
                .unwrap();
            if reply
                .entries
                .iter()
                .any(|entry| entry.call_key == format!("pf:capture-{corr}"))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("drain disposes and settles the capture");
    // A draining dispatcher admits no new pulls. Resume fixture admission
    // only after the background capture has observed the drain and ended.
    planes
        .draining
        .store(false, std::sync::atomic::Ordering::Release);
}

fn this_session() -> cingulate_client::live_call::SessionKey {
    computer_grants::tests::session_key("test-project")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capture_returns_pending_without_waiting_for_sign_in() {
    // The handoff lasts ten hang guards while the call is allowed one: a
    // reply that waits for sign-in cannot arrive under load before this
    // guard, so the outcome still proves the call handed off promptly.
    let fixture = login_capture::test_support::fixture_with(|env| {
        env.handoff_duration = HANG_GUARD * 10;
        env.poll_interval = Duration::from_millis(20);
    });
    fixture.launcher.script.lock().unwrap().logs_in = false;
    let cingulate = ScriptedConsent::new();
    cingulate
        .raises("el_cap_prompt")
        .answered_in_call("el_cap_prompt", "allow");
    let planes = cingulate.planes(&fixture);
    let (tx, mut rx) = mpsc::channel(8);
    let reply = tokio::time::timeout(
        HANG_GUARD,
        capture_initial_reply(&planes, &tx, &mut rx, 340, ollama_capture_params()),
    )
    .await
    .expect("consent was answered; sign-in must not hold the call");
    assert_eq!(reply["outcome"], "capture_pending", "{reply}");
    assert_eq!(reply["origin"], "https://ollama.com");
    assert_eq!(reply["expires_in_ms"], (HANG_GUARD * 10).as_millis() as u64);
    assert!(reply["message"]
        .as_str()
        .unwrap()
        .contains("notice; do not poll"));
    assert_eq!(
        cingulate.methods().len(),
        2,
        "consent still completes in-call"
    );
    assert_eq!(fixture.vault.calls(), 0);
    let placement = fixture.launcher.placements.lock().unwrap()[0].clone();
    assert!(fixture.fs.exists(placement.profile_directory()));
    assert!(
        capture_provider_op(&planes, 4, "late_results", json!({})).await["entries"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    interrupt_capture(&planes, 340).await;
    assert_eq!(
        capture_late(&planes, 340).await["result"]["outcome"],
        "handoff_interrupted"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capture_late_entries_cover_all_endings_ack_and_custodian_isolation() {
    use login_capture::test_support::{fixture_with, ScriptedVerification};
    for (corr, expected) in [
        (341, "captured"),
        (342, "session_invalid"),
        (343, "expired"),
        (344, "handoff_interrupted"),
    ] {
        let fixture = fixture_with(|env| {
            env.handoff_duration = Duration::from_millis(150);
            env.poll_interval = Duration::from_millis(10);
        });
        {
            let mut script = fixture.launcher.script.lock().unwrap();
            if expected == "session_invalid" {
                script.verifications = vec![ScriptedVerification::redirected_off_origin()];
            } else if expected != "captured" {
                script.logs_in = false;
            }
        }
        let cingulate = ScriptedConsent::new();
        cingulate
            .raises("el_cap_end")
            .answered_in_call("el_cap_end", "allow");
        let planes = cingulate.planes(&fixture);
        let facts = planes.routes.get(4, 1).unwrap();
        planes.routes.insert(5, 1, AcceptedBindFacts::from_bind(
            &bind_identity_for_test(),
            Some(subc_protocol::Principal::Reserved { module_id: "striatum".into() }),
            Some(&json!({"agentProjectId":"test-project","sessionKind":"primary","effectiveCapabilityScope":["*"]})),
            None,
            &subc_protocol::RouteTarget::ToolProvider { module_id: "cerebellum".into() },
        ).with_scope(facts.scope.clone()));
        let (tx, mut rx) = mpsc::channel(8);
        let reply =
            capture_initial_reply(&planes, &tx, &mut rx, corr, ollama_capture_params()).await;
        assert_eq!(reply["outcome"], "capture_pending", "{reply}");
        if expected == "handoff_interrupted" {
            interrupt_capture(&planes, corr).await;
        }
        let entry = capture_late(&planes, corr).await;
        assert_eq!(
            entry["result"],
            json!({"outcome":expected,"origin":"https://ollama.com"})
        );
        assert_eq!(entry["kind"], "result");
        assert_eq!(
            entry["custodian"],
            journal::call_records::principal_label(facts.principal.as_ref())
        );
        assert_eq!(entry["call_key"], format!("pf:capture-{corr}"));
        assert!(entry["settled_at"].as_u64().unwrap() > 0);
        browser::validate_browser_result(management::CAPTURE_LOGIN, &entry["result"]).unwrap();
        assert!(
            capture_provider_op(&planes, 5, "late_results", json!({})).await["entries"]
                .as_array()
                .unwrap()
                .is_empty(),
            "another custodian received the capture result"
        );
        let all = capture_provider_op(&planes, 4, "late_results", json!({})).await;
        assert_eq!(
            capture_provider_op(
                &planes,
                4,
                "late_results.ack",
                json!({"through":all["cursor"]})
            )
            .await,
            json!({})
        );
        assert!(
            capture_provider_op(&planes, 4, "late_results", json!({})).await["entries"]
                .as_array()
                .unwrap()
                .is_empty(),
            "ack must remove the entry"
        );
        let replay =
            capture_initial_reply(&planes, &tx, &mut rx, corr, ollama_capture_params()).await;
        assert_eq!(
            replay["outcome"], expected,
            "an acknowledged call must not recreate a pending capture"
        );
        assert_eq!(
            fixture
                .launcher
                .launches
                .load(std::sync::atomic::Ordering::Acquire),
            1
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capture_v4_floor_is_lazy_and_present_remains_v3() {
    use cerebellum_core::format_floor::{read_floors, DurableFormat, FormatFloor};
    use journal::call_records::{Begin, CallRecords, FilesystemCallRecordStorage, ScopeIdentity};
    let fixture = login_capture::test_support::fixture();
    fixture.launcher.script.lock().unwrap().logs_in = false;
    let cingulate = ScriptedConsent::new();
    cingulate
        .raises("el_cap_floor")
        .answered_in_call("el_cap_floor", "allow");
    let path = cingulate.dir.join("call_records.jsonl");
    let floor_path = cingulate.dir.join("format-floor.json");
    let mut planes = cingulate.planes(&fixture);
    planes.calls = Arc::new(CallRecords::open(
        Box::new(
            FilesystemCallRecordStorage::new(path.clone())
                .with_format_floor(FormatFloor::at(&floor_path)),
        ),
        wall_clock_ms(),
    ));
    assert!(!path.exists());
    assert!(
        !floor_path.exists(),
        "starting the build must not close rollback"
    );
    let facts = planes.routes.get(4, 1).unwrap();
    let principal = journal::call_records::principal_label(facts.principal.as_ref());
    assert!(matches!(
        planes.calls.begin(
            &principal,
            "pf:present-only",
            &facts.identity.conversation_key,
            wall_clock_ms()
        ),
        Begin::Execute(_)
    ));
    assert_eq!(
        read_floors(&floor_path).unwrap().get("call-records"),
        Some(&2)
    );
    planes
        .calls
        .hold_handoff(
            &principal,
            "pf:present-only",
            &facts.identity.conversation_key,
            ScopeIdentity::from_stamp(facts.scope.as_ref().unwrap()),
            "https://ollama.com",
            wall_clock_ms(),
        )
        .unwrap();
    let present_only = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        present_only.lines().next(),
        Some("{\"format\":\"call-records\",\"version\":3}")
    );
    assert_eq!(
        read_floors(&floor_path).unwrap().get("call-records"),
        Some(&3)
    );
    assert!(!present_only.contains("\"capture\""));
    let (tx, mut rx) = mpsc::channel(8);
    assert_eq!(
        capture_initial_reply(&planes, &tx, &mut rx, 347, ollama_capture_params()).await["outcome"],
        "capture_pending"
    );
    let captured = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        captured.lines().next(),
        Some("{\"format\":\"call-records\",\"version\":4}")
    );
    assert!(captured.contains("\"capture\":true"));
    assert_eq!(
        read_floors(&floor_path).unwrap().get("call-records"),
        Some(&4)
    );
    let header: Value = serde_json::from_str(captured.lines().next().unwrap()).unwrap();
    assert!(
        DurableFormat::new("call-records", 3)
            .refuse_newer(header["version"].as_u64().unwrap())
            .is_err(),
        "a v3 reader must refuse before decoding capture state"
    );
    assert!(crate::durable_formats::readable_formats()
        .contains(&journal::call_records::CALL_RECORD_FORMAT));
    interrupt_capture(&planes, 347).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capture_restart_settles_interrupted_and_preserves_retention_and_format() {
    use journal::call_records::{CallRecords, FilesystemCallRecordStorage};
    let fixture = login_capture::test_support::fixture();
    fixture.launcher.script.lock().unwrap().logs_in = false;
    let cingulate = ScriptedConsent::new();
    cingulate
        .raises("el_cap_restart")
        .answered_in_call("el_cap_restart", "allow");
    let path = cingulate.dir.join("call_records.jsonl");
    let store = || {
        CallRecords::open(
            Box::new(FilesystemCallRecordStorage::new(path.clone())),
            wall_clock_ms(),
        )
    };
    let mut planes = cingulate.planes(&fixture);
    planes.calls = Arc::new(store());
    // Merely opening capture-capable planes does not write new state.
    assert!(!path.exists());
    let (tx, mut rx) = mpsc::channel(8);
    assert_eq!(
        capture_initial_reply(&planes, &tx, &mut rx, 345, ollama_capture_params()).await["outcome"],
        "capture_pending"
    );
    let persisted = std::fs::read_to_string(&path).unwrap();
    assert!(
        persisted
            .lines()
            .any(|line| serde_json::from_str::<Value>(line).unwrap()["version"] == 4),
        "{persisted}"
    );
    assert!(!login_capture::test_support::contains_bytes(
        &persisted.into_bytes(),
        login_capture::test_support::PLANTED_VALUE
    ));
    let mut restarted = cingulate.planes(&fixture);
    restarted.calls = Arc::new(store());
    let entry = capture_late(&restarted, 345).await;
    assert_eq!(entry["result"]["outcome"], "handoff_interrupted");
    let principal = journal::call_records::principal_label(
        restarted.routes.get(4, 1).unwrap().principal.as_ref(),
    );
    let settled_at = entry["settled_at"].as_u64().unwrap();
    let request = cortexkit_role_tool_provider::late_results::LateResultsRequest::new();
    let before = restarted
        .calls
        .late_results(&principal, &request, settled_at + 24 * 60 * 60 * 1_000 - 1)
        .unwrap();
    assert_eq!(before.entries[0].kind, "result");
    let after = restarted
        .calls
        .late_results(&principal, &request, settled_at + 24 * 60 * 60 * 1_000 + 1)
        .unwrap();
    assert_eq!(after.entries[0].kind, "expired");
    assert!(after.entries[0].result.is_none());
    interrupt_capture(&planes, 345).await;
    capture_late(&planes, 345).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unkeyed_capture_is_refused_before_consent_or_browser_launch() {
    let fixture = login_capture::test_support::fixture();
    let cingulate = ScriptedConsent::new();
    let planes = cingulate.planes(&fixture);
    let mut frame = capture_request_frame(346, ollama_capture_params());
    let mut body: Value = serde_json::from_slice(&frame.body).unwrap();
    body.as_object_mut().unwrap().remove("call_key");
    frame.body = serde_json::to_vec(&body).unwrap();
    let (tx, mut rx) = mpsc::channel(8);
    handle_frame(frame, &tx, &planes).await.unwrap();
    let reply: Value = serde_json::from_slice(&next_frame(&mut rx).await.body).unwrap();
    assert_eq!(reply["outcome"], "invalid_request");
    assert_eq!(reply["detail"]["field"], "call_key");
    assert!(reply["detail"]["remedy"]
        .as_str()
        .unwrap()
        .contains("result arrives later"));
    assert!(cingulate.methods().is_empty());
    assert_eq!(
        fixture
            .launcher
            .launches
            .load(std::sync::atomic::Ordering::Acquire),
        0
    );
}

#[tokio::test]
async fn capture_login_without_live_carrier_refuses_before_readiness_or_effects() {
    use login_capture::test_support::{fixture, fixture_without_launcher};
    use std::sync::atomic::Ordering;

    for configured in [false, true] {
        let fixture = if configured {
            fixture()
        } else {
            fixture_without_launcher()
        };
        let cingulate = ScriptedConsent::new();
        let planes = cingulate.planes(&fixture);
        let admitted = planes.routes.get(4, 1).unwrap();
        assert!(computer_grants::admits_consent(&admitted));
        let facts = admitted.clone().with_scope(None);
        planes.routes.insert(4, 1, facts);
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
        let reply = capture_initial_reply(
            &planes,
            &writer_tx,
            &mut writer_rx,
            401,
            ollama_capture_params(),
        )
        .await;

        // A call without an admitted agent session gets the same refusal
        // whether or not a browser executable is configured; it cannot ask
        // the person to approve it.
        assert_eq!(reply["outcome"], "consent_unavailable", "{reply}");
        assert_eq!(reply["detail"]["reason"], "no_agent_session", "{reply}");

        // An admitted route is not sufficient after its call has ended. The
        // frame dispatcher normally installs an in-flight guard; invoking
        // this production handler without it exercises RouteCarrier::live's
        // CallEnded refusal before browser configuration is examined.
        planes.routes.insert(4, 1, admitted.clone());
        let request = login_capture::CaptureRequest {
            credential_domain: "ollama.com".into(),
            account: "work".into(),
            fetch_url: "https://ollama.com/settings".into(),
            login_url: "https://ollama.com/login".into(),
        };
        let consent = login_consent_request(
            &planes,
            &admitted,
            &writer_tx,
            (4, 1),
            computer_grants::LoginCapability::CaptureLogin,
            request.consent_parameters(),
            None,
        );
        assert!(matches!(
            consent.carrier.live(),
            Err(cingulate_client::live_call::NotLive::CallEnded)
        ));
        let reply = capture_browser_login(
            &planes,
            &admitted,
            &writer_tx,
            (4, 1, 402),
            &request,
            "ended-capture-call",
        )
        .await;
        assert_eq!(reply["outcome"], "consent_unavailable", "{reply}");
        assert!(cingulate.methods().is_empty());
        assert_eq!(cingulate.script.opens(), 0);
        assert_eq!(fixture.launcher.launches.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.vault.opens.load(Ordering::SeqCst), 0);
        assert!(fixture.vault.requests.lock().unwrap().is_empty());
        assert!(fixture.fs.contents().is_empty());
        assert!(fixture.events.snapshot().is_empty());
    }
}

/// Through the production frame dispatcher and the Withhold reply boundary:
/// the planted cookie value reaches the vault request, and is absent from
/// the card put to the person, the pending reply, the late entry and every
/// decoded journal entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capture_login_keeps_the_value_out_of_the_reply_the_journal_and_the_ask() {
    use login_capture::test_support::{contains_bytes, fixture, PLANTED_VALUE};

    let fixture = fixture();
    let cingulate = ScriptedConsent::new();
    cingulate
        .raises("el_cap_301")
        .answered_in_call("el_cap_301", "allow");
    let mut planes = cingulate.planes(&fixture);
    let call_record_path = cingulate.dir.join("call_records.jsonl");
    planes.calls = Arc::new(journal::call_records::CallRecords::open(
        Box::new(journal::call_records::FilesystemCallRecordStorage::new(
            call_record_path.clone(),
        )),
        wall_clock_ms(),
    ));
    let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
    let journal_finalized = planes.capture.expect_journal_finalization();
    let body = capture_initial_reply(
        &planes,
        &writer_tx,
        &mut writer_rx,
        301,
        ollama_capture_params(),
    )
    .await;
    assert_eq!(body["outcome"], "capture_pending", "{body}");
    let late = capture_late(&planes, 301).await;
    assert_eq!(late["result"]["outcome"], "captured", "{late}");
    assert_eq!(
        cingulate.methods(),
        [
            cingulate_client::wire::CONSENT_REQUEST,
            cingulate_client::wire::CONSENT_AWAIT,
            cingulate_client::wire::CONSENT_REPORT_EXECUTION
        ]
    );
    let asked = cingulate.cards().remove(0);
    assert_eq!(asked["prompt"], "Save your ollama.com login for the agent?");
    // The Cingulate card id becomes the deposit's consent reference.
    assert_eq!(
        fixture.vault.request_params()[0]["consent_ref"],
        "el_cap_301"
    );
    assert!(planes.consent.unapplied(&this_session()).is_empty());

    // Positive control: the scanner finds the value where it was planted.
    let requests = fixture.vault.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 1);
    assert!(contains_bytes(&requests[0], PLANTED_VALUE));
    assert!(fixture.fs.files().is_empty());
    let cookie_bytes = fixture.vault.request_params()[0]["cookie"]
        .as_str()
        .unwrap()
        .len() as u64;

    assert!(
        !contains_bytes(&serde_json::to_vec(&asked).unwrap(), PLANTED_VALUE),
        "the card leaked it"
    );
    assert!(
        !contains_bytes(&serde_json::to_vec(&body).unwrap(), PLANTED_VALUE),
        "the reply leaked it"
    );
    assert!(
        !contains_bytes(&serde_json::to_vec(&late).unwrap(), PLANTED_VALUE),
        "the late entry leaked it"
    );
    assert!(
        !contains_bytes(&std::fs::read(call_record_path).unwrap(), PLANTED_VALUE),
        "the call-record journal leaked it"
    );
    // The late result deliberately precedes the detached audit write.
    tokio::time::timeout(HANG_GUARD, journal_finalized)
        .await
        .expect("the capture audit finishes")
        .expect("the capture signals its audit finalization");
    let export = planes.browser.journal_export_for_test().await;
    let entries = export
        .lines()
        .map(|line| serde_json::from_str::<journal::JournalEntry>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 1, "{export}");
    let Some(journal::JournalPayload::LoginCapture(payload)) = &entries[0].payload else {
        panic!("a capture is journaled with its own payload: {export}");
    };
    assert_eq!(payload.outcome, "captured:created");
    assert_eq!(payload.holder, "reserved:insula");
    assert_eq!(payload.credential_id, "cookie:ollama.com:work");
    assert_eq!(payload.bytes, cookie_bytes);
    assert_eq!(payload.deletion_succeeded, Some(true));
    for entry in &entries {
        let decoded = serde_json::to_vec(entry).unwrap();
        assert!(
            !contains_bytes(&decoded, PLANTED_VALUE),
            "the journal leaked it"
        );
        assert!(
            !contains_bytes(&decoded, "csrf"),
            "the journal named a cookie"
        );
    }
}

/// A successful settlement leaves only after the throwaway profile is
/// gone, even when deletion is slower than handing over the window.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capture_settlement_is_served_only_after_the_profile_is_deleted() {
    use login_capture::test_support::fixture;

    let fixture = fixture();
    *fixture.fs.removal_delay.lock().unwrap() = Duration::from_millis(200);
    let cingulate = ScriptedConsent::new();
    cingulate
        .raises("el_cap_302")
        .answered_in_call("el_cap_302", "allow");
    let planes = cingulate.planes(&fixture);
    let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
    let body = capture_reply(
        &planes,
        &writer_tx,
        &mut writer_rx,
        302,
        ollama_capture_params(),
    )
    .await;
    assert_eq!(body["outcome"], "captured", "{body}");
    let placement = fixture.launcher.placements.lock().unwrap()[0].clone();
    assert!(
        !fixture.fs.exists(placement.profile_directory()),
        "the reply was sent while the throwaway profile still existed"
    );
    assert!(fixture
        .events
        .snapshot()
        .contains(&"profile_deleted".to_string()));
}

/// A cancel frame for the request, arriving while the card is open, ends
/// the capture with nothing written. The card is detached rather than
/// withdrawn, since the conversation is still there: the person may still
/// answer it, and that answer is kept for a retry rather than acted on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancel_during_consent_ends_the_capture_and_leaves_its_card_open() {
    use login_capture::test_support::fixture;

    let fixture = fixture();
    let cingulate = ScriptedConsent::new();
    cingulate.raises("el_cap_303");
    cingulate
        .script
        .then(
            cingulate_client::wire::CONSENT_AWAIT,
            cingulate_client::Reply::Hang,
        )
        .then(
            cingulate_client::wire::CONSENT_DETACH,
            cingulate_client::Reply::Result(
                json!({"elicitation_id": "el_cap_303", "state": "pending", "detached": true}),
            ),
        );
    let planes = cingulate.planes(&fixture);
    let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
    let request = capture_request_frame(303, ollama_capture_params());
    handle_frame_for_test(request.clone(), &writer_tx, &planes)
        .await
        .unwrap();
    tokio::time::timeout(HANG_GUARD, async {
        while cingulate.methods().len() < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the call waits on its card");
    let cancel = Frame::build_with_version(
        subc_protocol::PROTOCOL_VERSION,
        FrameType::Cancel,
        Flags::new(false, Priority::Interactive, false),
        4,
        1,
        303,
        Vec::new(),
    )
    .unwrap();
    handle_frame_for_test(cancel.clone(), &writer_tx, &planes)
        .await
        .unwrap();
    let reply = next_frame(&mut writer_rx).await;
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(body, json!({"context":null,"outcome":"cancelled"}));
    crate::turn_stop_vectors::check(
        "capture-login-card",
        "parked awaiting the 30-minute capture card before login handoff",
        &request,
        &cancel,
        Some(&reply),
    );
    tokio::time::timeout(HANG_GUARD, async {
        while cingulate.methods().len() < 3 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the cancelled call lets go of its card");
    assert_eq!(
        cingulate.methods(),
        [
            cingulate_client::wire::CONSENT_REQUEST,
            cingulate_client::wire::CONSENT_AWAIT,
            cingulate_client::wire::CONSENT_DETACH
        ]
    );
    // The card outlives the cancelled call, so an answer to it is still
    // received; it is remembered, and nothing runs on it.
    assert_eq!(
        planes.consent.unapplied(&this_session()).len(),
        1,
        "the cancelled capture closed its card"
    );
    cingulate.feed(late_answer("el_cap_303", "allow"));
    await_remembered(&planes, true).await;
    assert!(fixture.fs.contents().is_empty());
    assert_eq!(
        fixture
            .launcher
            .launches
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

/// Which part of a cancelled capture finishes first, named for that part.
#[derive(Clone, Copy, Debug)]
enum CaptureCancelOrdering {
    /// The capture's own polling notices the cancel and ends the capture
    /// while Cingulate is still answering the card's detach.
    CapturePoll,
    /// The card wait, woken by the same cancel, ends the capture as soon
    /// as the detach is answered, before the capture's polling runs.
    ConsentWait,
    /// The turn stop sends its reply when its cleanup time runs out, and
    /// the capture ends only afterwards.
    TurnStop,
}

/// A capture_login cancelled while its card is open is answered with the
/// turn-stop vector's bytes, exactly once, whichever part of the call
/// finishes first, and the capture records itself as cancelled. Each
/// ordering is forced: the test holds Cingulate's detach reply, and time
/// is paused, so the capture's polling and the turn stop's cleanup
/// deadline run only when every task is waiting.
#[tokio::test(start_paused = true)]
async fn a_cancelled_capture_sends_the_turn_stop_bytes_in_every_ordering() {
    use login_capture::test_support::fixture;

    for ordering in [
        CaptureCancelOrdering::CapturePoll,
        CaptureCancelOrdering::ConsentWait,
        CaptureCancelOrdering::TurnStop,
    ] {
        let fixture = fixture();
        let cingulate = ScriptedConsent::new();
        let (detach_called, detach_started) = tokio::sync::oneshot::channel();
        let (detach_reply, detach_response) = tokio::sync::oneshot::channel();
        cingulate.raises("el_cap_303");
        cingulate
            .script
            .then(
                cingulate_client::wire::CONSENT_AWAIT,
                cingulate_client::Reply::Hang,
            )
            .then(
                cingulate_client::wire::CONSENT_DETACH,
                cingulate_client::Reply::Controlled {
                    called: detach_called,
                    reply: detach_response,
                },
            );
        let planes = cingulate.planes(&fixture);
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
        let request = capture_request_frame(303, ollama_capture_params());
        handle_frame_for_test(request.clone(), &writer_tx, &planes)
            .await
            .unwrap();
        tokio::time::timeout(HANG_GUARD, async {
            while cingulate.methods().len() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the call waits on its card");
        let cancel = crate::turn_stop_vectors::cancel(&request);
        handle_frame_for_test(cancel.clone(), &writer_tx, &planes)
            .await
            .unwrap();
        tokio::time::timeout(HANG_GUARD, detach_started)
            .await
            .expect("the cancel detaches the card")
            .unwrap();
        let detached =
            json!({"elicitation_id": "el_cap_303", "state": "pending", "detached": true});
        let reply = match ordering {
            CaptureCancelOrdering::CapturePoll => {
                // Paused time moves only while every task waits, so the
                // capture's polling (every millisecond in this fixture)
                // sees the cancel before the detach is answered.
                tokio::time::sleep(Duration::from_millis(10)).await;
                detach_reply.send(detached).unwrap();
                next_frame(&mut writer_rx).await
            }
            CaptureCancelOrdering::ConsentWait => {
                // No time passes, so the polling timer cannot fire: the
                // answered detach is what ends the capture.
                detach_reply.send(detached).unwrap();
                next_frame(&mut writer_rx).await
            }
            CaptureCancelOrdering::TurnStop => {
                let reply = next_frame(&mut writer_rx).await;
                assert!(
                    planes.browser.journal_export_for_test().await.is_empty(),
                    "the capture ended before the turn stop replied"
                );
                detach_reply.send(detached).unwrap();
                reply
            }
        };
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(
            body,
            json!({"context":null,"outcome":"cancelled"}),
            "{ordering:?}"
        );
        crate::turn_stop_vectors::check(
            "capture-login-card",
            "parked awaiting the 30-minute capture card before login handoff",
            &request,
            &cancel,
            Some(&reply),
        );
        // The capture journals how it ended as its last step, so once the
        // entry is there the capture has finished and sent all it will.
        let export = tokio::time::timeout(HANG_GUARD, async {
            loop {
                let export = planes.browser.journal_export_for_test().await;
                if !export.is_empty() {
                    break export;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the cancelled capture ends");
        let entries = export
            .lines()
            .map(|line| serde_json::from_str::<journal::JournalEntry>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 1, "{ordering:?}: {export}");
        let Some(journal::JournalPayload::LoginCapture(payload)) = &entries[0].payload else {
            panic!("{ordering:?}: a capture is journaled with its own payload: {export}");
        };
        assert_eq!(payload.outcome, "cancelled", "{ordering:?}");
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
        assert!(
            writer_rx.try_recv().is_err(),
            "{ordering:?}: a cancelled capture was answered twice"
        );
        assert!(fixture.fs.contents().is_empty());
    }
}

/// Apply a late login answer through the session's next call, then check
/// whether its approval or explicit refusal was remembered.
async fn await_remembered(planes: &Planes, expected: bool) {
    computer_grants::tests::drain_call(planes, 4, 1).await;
    assert_eq!(
        planes.consent.has_single_use_approvals()
            || planes.management.computer_grants().remembers_login_answer(),
        expected
    );
}

/// Older consent servers receive the original thirty-minute deadline.
/// Late approval can authorize a matching retry, not launch a capture itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_capture_card_is_sent_for_thirty_minutes_with_late_execution() {
    use login_capture::test_support::fixture;

    let fixture = fixture();
    let cingulate = ScriptedConsent::new();
    cingulate.raises("el_cap_310").unanswered("el_cap_310");
    let planes = cingulate.planes(&fixture);
    let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
    let body = capture_reply(
        &planes,
        &writer_tx,
        &mut writer_rx,
        310,
        ollama_capture_params(),
    )
    .await;
    assert_eq!(body["outcome"], "consent_pending", "{body}");
    let asked = cingulate.cards().remove(0);
    assert_eq!(asked["expires_in_ms"], 1_800_000, "{asked}");
    assert_eq!(asked["late_execution"], "execute", "{asked}");
}

/// Unanswered, the capture call holds the card for the park (Cingulate
/// is asked to wait that long), then detaches it and replies
/// `consent_pending` naming it. The card stays registered, so a later
/// answer is still received.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unanswered_capture_replies_consent_pending_after_the_park_and_keeps_its_card() {
    use login_capture::test_support::fixture;

    let fixture = fixture();
    let cingulate = ScriptedConsent::new();
    cingulate.raises("el_cap_311").unanswered("el_cap_311");
    let planes = cingulate.planes(&fixture);
    assert_eq!(
        planes.management.computer_grants().login_park_limit(),
        Duration::from_secs(120)
    );
    let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
    let body = capture_reply(
        &planes,
        &writer_tx,
        &mut writer_rx,
        311,
        ollama_capture_params(),
    )
    .await;
    assert_eq!(body["outcome"], "consent_pending", "{body}");
    assert_eq!(body["ask_id"], "el_cap_311", "{body}");
    assert_eq!(
        body["remedy"],
        computer_grants::LOGIN_CONSENT_PENDING_REMEDY,
        "{body}"
    );
    assert_eq!(
        cingulate.methods(),
        [
            cingulate_client::wire::CONSENT_REQUEST,
            cingulate_client::wire::CONSENT_AWAIT,
            cingulate_client::wire::CONSENT_DETACH
        ]
    );
    let held_for = cingulate.script.calls()[1].1["timeout_ms"]
        .as_u64()
        .unwrap();
    assert!(
        (110_000..=120_000).contains(&held_for),
        "the call held its card for {held_for} ms, not the park"
    );
    assert_eq!(
        planes.consent.unapplied(&this_session()).len(),
        1,
        "the card was closed when the call returned"
    );
    assert!(fixture.fs.contents().is_empty());
}

/// An approval that arrives after the call returned is used by the next
/// call with the same parameters, which captures without a second card,
/// names the approved card as its consent, and tells Cingulate the
/// approved capture ran before settlement. A call with other parameters
/// does not use it, and once used it is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_late_capture_approval_is_used_once_by_a_retry_with_the_same_parameters() {
    use cingulate_client::wire::{
        CONSENT_ACK, CONSENT_ANSWERS, CONSENT_AWAIT, CONSENT_DETACH, CONSENT_REPORT_EXECUTION,
        CONSENT_REQUEST,
    };
    use login_capture::test_support::fixture;

    let fixture = fixture();
    let cingulate = ScriptedConsent::new();
    cingulate.raises("el_cap_320").unanswered("el_cap_320");
    let planes = cingulate.planes(&fixture);
    let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(16);
    let first = capture_reply(
        &planes,
        &writer_tx,
        &mut writer_rx,
        320,
        ollama_capture_params(),
    )
    .await;
    assert_eq!(first["outcome"], "consent_pending", "{first}");
    cingulate.feed(late_answer("el_cap_320", "allow"));
    await_remembered(&planes, true).await;
    assert_eq!(
        fixture.vault.request_params().len(),
        0,
        "ran on a late answer"
    );

    // Another account: the approval is not for it, so it gets a card of
    // its own.
    let mut other = ollama_capture_params();
    other["account"] = json!("personal");
    cingulate.raises("el_cap_321").unanswered("el_cap_321");
    let second = capture_reply(&planes, &writer_tx, &mut writer_rx, 321, other).await;
    assert_eq!(second["ask_id"], "el_cap_321", "{second}");
    assert!(planes.consent.has_single_use_approvals());

    // The same parameters: the approval is taken, the capture runs, and
    // its execution is reported before settlement. The session's open
    // card for the other account makes this call read the answers feed
    // first, which has nothing new.
    cingulate.feed(json!([])).takes_report("el_cap_320");
    let before = cingulate.methods().len();
    let body = capture_reply(
        &planes,
        &writer_tx,
        &mut writer_rx,
        322,
        ollama_capture_params(),
    )
    .await;
    assert_eq!(body["outcome"], "captured", "{body}");
    assert_eq!(
        cingulate.methods()[before..],
        [CONSENT_ANSWERS, CONSENT_ACK, CONSENT_REPORT_EXECUTION],
        "a taken approval must be reported before settlement, with no second card"
    );
    assert_eq!(
        cingulate.script.calls().last().unwrap().1,
        json!({"elicitation_id":"el_cap_320", "execution":"executed"})
    );
    assert_eq!(
        fixture.vault.request_params()[0]["consent_ref"],
        "el_cap_320"
    );
    assert!(
        !(planes.consent.has_single_use_approvals()
            || planes.management.computer_grants().remembers_login_answer())
    );

    // Used once: the next call asks again.
    cingulate
        .feed(json!([]))
        .raises("el_cap_323")
        .unanswered("el_cap_323");
    let before = cingulate.methods().len();
    let again = capture_reply(
        &planes,
        &writer_tx,
        &mut writer_rx,
        323,
        ollama_capture_params(),
    )
    .await;
    assert_eq!(again["outcome"], "consent_pending", "{again}");
    assert_eq!(
        cingulate.methods()[before..],
        [
            CONSENT_ANSWERS,
            CONSENT_ACK,
            CONSENT_REQUEST,
            CONSENT_AWAIT,
            CONSENT_DETACH
        ]
    );
    assert_eq!(fixture.vault.request_params().len(), 1);
}

/// A capture approval given after its call returned survives a module
/// restart: the restarted module's next call on the session reads it
/// from the answers feed, acknowledges it, uses it once and reports that
/// the capture ran, all before it replies. A second restart has nothing
/// left to apply and opens no route to Cingulate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_late_capture_approval_survives_a_restart_and_is_applied_once() {
    use cingulate_client::desk::RegistryStore;
    use cingulate_client::wire::{CONSENT_ACK, CONSENT_ANSWERS, CONSENT_REPORT_EXECUTION};
    use login_capture::test_support::fixture;

    let fixture = fixture();
    let cingulate = ScriptedConsent::new();
    cingulate.raises("el_cap_360").unanswered("el_cap_360");
    let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(16);
    {
        let planes = cingulate.planes(&fixture);
        let first = capture_reply(
            &planes,
            &writer_tx,
            &mut writer_rx,
            360,
            ollama_capture_params(),
        )
        .await;
        assert_eq!(first["outcome"], "consent_pending", "{first}");
    }
    assert_eq!(cingulate.store().load().unwrap().len(), 1);

    // The person approves while the module is down.
    let restarted = cingulate.planes(&fixture);
    cingulate
        .feed(late_answer("el_cap_360", "allow"))
        .takes_report("el_cap_360");
    let before = cingulate.methods().len();
    let body = capture_reply(
        &restarted,
        &writer_tx,
        &mut writer_rx,
        361,
        ollama_capture_params(),
    )
    .await;
    assert_eq!(body["outcome"], "captured", "{body}");
    assert_eq!(
        cingulate.methods()[before..],
        [CONSENT_ANSWERS, CONSENT_ACK, CONSENT_REPORT_EXECUTION]
    );
    assert_eq!(
        cingulate.script.calls().last().unwrap().1,
        json!({"elicitation_id":"el_cap_360", "execution":"executed"})
    );
    assert_eq!(fixture.vault.request_params().len(), 1);
    assert_eq!(
        fixture.vault.request_params()[0]["consent_ref"],
        "el_cap_360"
    );
    assert!(cingulate
        .store()
        .load()
        .unwrap()
        .iter()
        .all(|card| card.applied && card.lifecycle.acked));
    assert!(!restarted.consent.has_single_use_approvals());

    let again = cingulate.planes(&fixture);
    let opens = cingulate.script.opens();
    computer_grants::tests::drain_call(&again, 4, 1).await;
    assert_eq!(cingulate.script.opens(), opens, "nothing was left to apply");
    assert!(!again.consent.has_single_use_approvals());
    assert_eq!(fixture.vault.request_params().len(), 1);
}

/// A refusal that arrives after the call returned refuses the retry
/// with the same parameters as declined, without a second card.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_late_capture_refusal_declines_the_retry_without_a_card() {
    use login_capture::test_support::fixture;

    let fixture = fixture();
    let cingulate = ScriptedConsent::new();
    cingulate.raises("el_cap_330").unanswered("el_cap_330");
    let planes = cingulate.planes(&fixture);
    let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(16);
    let first = capture_reply(
        &planes,
        &writer_tx,
        &mut writer_rx,
        330,
        ollama_capture_params(),
    )
    .await;
    assert_eq!(first["outcome"], "consent_pending", "{first}");
    cingulate.feed(late_answer("el_cap_330", "deny"));
    await_remembered(&planes, true).await;
    let before = cingulate.cards().len();
    let body = capture_reply(
        &planes,
        &writer_tx,
        &mut writer_rx,
        331,
        ollama_capture_params(),
    )
    .await;
    assert_eq!(body["outcome"], "capture_consent_not_given", "{body}");
    assert_eq!(body["reason"], "deny", "{body}");
    assert_eq!(cingulate.cards().len(), before, "a second card was raised");
    assert_eq!(
        fixture
            .launcher
            .launches
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

/// A retry while the card is still unanswered waits on that card rather
/// than filing a second one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_capture_retry_while_its_card_is_open_rejoins_it() {
    use cingulate_client::wire::{CONSENT_ACK, CONSENT_ANSWERS, CONSENT_AWAIT, CONSENT_DETACH};
    use login_capture::test_support::fixture;

    let fixture = fixture();
    let cingulate = ScriptedConsent::new();
    cingulate.raises("el_cap_340").unanswered("el_cap_340");
    let planes = cingulate.planes(&fixture);
    let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(16);
    let first = capture_reply(
        &planes,
        &writer_tx,
        &mut writer_rx,
        340,
        ollama_capture_params(),
    )
    .await;
    cingulate.feed(json!([])).unanswered("el_cap_340");
    let before = cingulate.methods().len();
    let second = capture_reply(
        &planes,
        &writer_tx,
        &mut writer_rx,
        341,
        ollama_capture_params(),
    )
    .await;
    assert_eq!(second["outcome"], "consent_pending", "{second}");
    assert_eq!(second["ask_id"], first["ask_id"], "{second}");
    assert_eq!(
        cingulate.methods()[before..],
        [CONSENT_ANSWERS, CONSENT_ACK, CONSENT_AWAIT, CONSENT_DETACH],
        "the retry raised a second card"
    );
    assert_eq!(planes.consent.unapplied(&this_session()).len(), 1);
    // The one card still answers the agent's next retry.
    cingulate.feed(late_answer("el_cap_340", "allow"));
    await_remembered(&planes, true).await;
}

/// Revoking the session scope drops an approval that arrived after its
/// call returned, so the next call asks again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scope_revocation_drops_a_late_capture_approval() {
    use login_capture::test_support::fixture;

    let fixture = fixture();
    let cingulate = ScriptedConsent::new();
    cingulate.raises("el_cap_350").unanswered("el_cap_350");
    let planes = cingulate.planes(&fixture);
    let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(16);
    capture_reply(
        &planes,
        &writer_tx,
        &mut writer_rx,
        350,
        ollama_capture_params(),
    )
    .await;
    cingulate.feed(late_answer("el_cap_350", "allow"));
    await_remembered(&planes, true).await;
    let conversation = planes.routes.get(4, 1).unwrap().identity.conversation_key;
    revoke_scope(&planes, &std::collections::BTreeSet::from([conversation])).await;
    assert!(
        !(planes.consent.has_single_use_approvals()
            || planes.management.computer_grants().remembers_login_answer())
    );
    cingulate.raises("el_cap_351").unanswered("el_cap_351");
    let pending = capture_reply(
        &planes,
        &writer_tx,
        &mut writer_rx,
        351,
        ollama_capture_params(),
    )
    .await;
    assert_eq!(pending["outcome"], "consent_pending", "{pending}");
    assert_eq!(fixture.vault.request_params().len(), 0);
    assert_eq!(planes.consent.unapplied(&this_session()).len(), 1);
    // The revocation also forgets a card still open, so its answer is
    // received by nothing, and it opens no route to Cingulate.
    let calls = cingulate.methods().len();
    let conversation = planes.routes.get(4, 1).unwrap().identity.conversation_key;
    revoke_scope(&planes, &std::collections::BTreeSet::from([conversation])).await;
    assert!(
        planes.consent.unapplied(&this_session()).is_empty(),
        "the open card was not forgotten"
    );
    assert_eq!(cingulate.methods().len(), calls);
    assert!(
        writer_rx.try_recv().is_err(),
        "revocation sends nothing on the route"
    );
    assert!(!planes
        .management
        .computer_grants()
        .question_open(pending["ask_id"].as_str().unwrap()));
}

/// When Cingulate refuses to raise the card (the requester is refused),
/// the capture ends at once with `not_put_to_anyone`: nobody was shown
/// the card, which is not the same as a person who saw it and stayed
/// silent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_requester_refusal_ends_the_capture_as_not_put_to_anyone() {
    use login_capture::test_support::fixture;

    let fixture = fixture();
    let cingulate = ScriptedConsent::new();
    cingulate.script.then(
        cingulate_client::wire::CONSENT_REQUEST,
        cingulate_client::Reply::Refused("elicitation_requester_refused"),
    );
    let planes = cingulate.planes(&fixture);
    let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
    let body = capture_reply(
        &planes,
        &writer_tx,
        &mut writer_rx,
        304,
        ollama_capture_params(),
    )
    .await;
    assert_eq!(body["outcome"], "capture_consent_not_given", "{body}");
    assert_eq!(body["reason"], "not_put_to_anyone", "{body}");
    assert_eq!(
        cingulate.methods(),
        [cingulate_client::wire::CONSENT_REQUEST]
    );
    assert!(planes.consent.unapplied(&this_session()).is_empty());
    assert!(fixture.fs.contents().is_empty());
}

#[tokio::test]
async fn capture_login_params_are_exactly_closed() {
    use login_capture::test_support::fixture;

    let fixture = fixture();
    let planes = capture_planes(&fixture);
    let mut missing_account = ollama_capture_params();
    missing_account.as_object_mut().unwrap().remove("account");
    let mut extra = ollama_capture_params();
    extra["holder"] = json!("someone-else");
    for (correlation, (params, field, reason)) in [
        (missing_account, "account", "missing_field"),
        (extra, "holder", "unknown_field"),
    ]
    .into_iter()
    .enumerate()
    {
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
        handle_route_request(
            capture_request_frame(310 + correlation as u64, params),
            &writer_tx,
            &planes,
        )
        .await
        .unwrap();
        let body: Value = serde_json::from_slice(&next_frame(&mut writer_rx).await.body).unwrap();
        assert_eq!(body["outcome"], "invalid_request", "{body}");
        assert_eq!(body["detail"]["field"], field, "{body}");
        assert_eq!(body["detail"]["reason_code"], reason, "{body}");
    }
    assert!(fixture.events.snapshot().is_empty());
}

/// The capture reply schema is closed at the module's own boundary: an
/// undeclared field or a missing outcome is withheld rather than sent.
#[test]
fn the_capture_reply_boundary_withholds_what_the_schema_does_not_declare() {
    let planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::default()),
        None,
        JournalPersistence::Isolated,
    );
    assert!(planes
        .browser
        .finish_reply(
            management::CAPTURE_LOGIN,
            json!({"outcome": "captured", "cookie": "x"})
        )
        .is_err());
    assert!(planes
        .browser
        .finish_reply(management::CAPTURE_LOGIN, json!({"path": "/tmp/x"}))
        .is_err());
    // `commands` carried the `ck auth` commands a capture used to return
    // for storing its cookie file by hand; the schema no longer declares
    // it, so a reply carrying it is withheld.
    assert!(planes
        .browser
        .finish_reply(
            management::CAPTURE_LOGIN,
            json!({"outcome": "captured", "commands": ["ck auth put"]})
        )
        .is_err());
    assert!(planes
        .browser
        .finish_reply(
            management::CAPTURE_LOGIN,
            json!({"outcome": "captured", "credential_id": "cookie:x.com:a", "vault_outcome": "created", "record_version": 3})
        )
        .is_ok());
    assert!(planes
        .browser
        .finish_reply(
            management::CAPTURE_LOGIN,
            json!({"outcome": "captured", "vault_outcome": "kept"})
        )
        .is_err());
    assert!(planes
        .browser
        .finish_reply(management::CAPTURE_LOGIN, json!({"outcome": "made_up"}))
        .is_err());
    assert!(planes
        .browser
        .finish_reply(management::CAPTURE_LOGIN, json!({"outcome": "cancelled"}))
        .is_ok());
}

/// A route bound to a surface this module does not serve is refused as such.
///
/// Not served as either of the surfaces it does: answering from an envelope
/// the caller did not use produces a reply about a request nobody made.
#[tokio::test]
async fn an_unsupported_surface_is_refused_by_name() {
    let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
    let planes = Planes {
        private_content: Arc::new(private_content::PrivateContent::in_memory()),
        agent_data: Arc::new(agent_data::Participant::in_memory()),
        image_handles: Arc::new(image_handles::ImageHandles::default()),
        signed_in: Arc::new(browser_signed_in::SignedInDomains::default()),
        cancellations: RequestCancellations::default(),
        operator_confirm: Arc::default(),
        run_calls: codemode::RunCalls::default(),
        browser_resumes: Arc::default(),
        browser_queue: Arc::new(call_queue::ConversationQueue::default()),
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        computer_admitted: test_admitted_computer_capabilities(),
        health: Arc::new(HealthState::default()),
        routes: Arc::new(RouteBindings::new()),
        browser: Arc::new(BrowserPlane::new()),
        browser_config: None,
        runtime_browser: None,
        sessions: browser_session::BrowserSessions::default(),
        user_browser: user_browser_bridge::UserBrowserBridge::new(),
        lease_clock: Arc::new(cerebellum_core::clock::SystemClock::new()),
        launch_service: None,
        management: test_management_plane(),
        consent: Arc::new(cingulate_client::desk::ConsentDesk::new(Arc::new(
            consent_drain::UnconfiguredCingulate,
        ))),
        consent_drain: Arc::new(consent_drain::ConsentDrain::default()),
        user_browser_cards: Arc::default(),
        #[cfg(test)]
        consent_test: None,
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        computer: Err(computer_capability::ComputerPlaneUnavailable::CaptureCustody),
        #[cfg(test)]
        route_test_handler: None,
        #[cfg(test)]
        cursor_for_test: None,
        #[cfg(all(test, target_os = "macos"))]
        computer_for_test: None,
        draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        drain_signal: Arc::new(tokio::sync::watch::channel(false).0),
        drain_notice: Arc::new(std::sync::OnceLock::new()),
        capture: login_capture::test_support::fixture().module,
        calls: Arc::new(journal::call_records::CallRecords::in_memory()),
        call_record_workers: Arc::new(CallRecordWorkers::default()),
        egress_deadlines: Arc::new(ConnectionDeadlines::default()),
        scopes: Arc::new(scope_watch::ScopeRevocation::default()),
    };
    planes.routes.insert(
        6,
        1,
        AcceptedBindFacts::from_bind(
            &bind_identity_for_test(),
            Some(Principal::Direct),
            None,
            None,
            &subc_protocol::RouteTarget::InternalService {
                module_id: "cerebellum".to_string(),
                service_id: "anything".to_string(),
            },
        ),
    );

    let frame = Frame::build_with_version(
        subc_protocol::PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        6,
        1,
        78,
        b"{}".to_vec(),
    )
    .unwrap();

    handle_route_request(frame, &writer_tx, &planes)
        .await
        .expect("an unsupported surface is answered");

    // A transport-level error rather than an application outcome: no
    // operation ran, so there is no result to report. The surface is named
    // in the code so a caller can tell this from a request it got wrong.
    let response = writer_rx.recv().await.expect("a response frame");
    assert_eq!(response.header.ty, FrameType::Error);
    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["code"], "unsupported_surface", "{body}");
}

fn bind_identity_for_test() -> subc_protocol::BindIdentity {
    subc_protocol::BindIdentity::new("test", "test-session".to_string())
}

/// Planes whose only route is bound to the management surface.
pub(super) fn management_bound_planes(channel: u16, epoch: u32) -> Planes {
    management_bound_planes_with_admission_facts(channel, epoch, None)
}

pub(super) fn management_bound_planes_with_admission_facts(
    channel: u16,
    epoch: u32,
    admission_facts: Option<&Value>,
) -> Planes {
    let planes = Planes {
        private_content: Arc::new(private_content::PrivateContent::in_memory()),
        agent_data: Arc::new(agent_data::Participant::in_memory()),
        image_handles: Arc::new(image_handles::ImageHandles::default()),
        signed_in: Arc::new(browser_signed_in::SignedInDomains::default()),
        cancellations: RequestCancellations::default(),
        operator_confirm: Arc::default(),
        run_calls: codemode::RunCalls::default(),
        browser_resumes: Arc::default(),
        browser_queue: Arc::new(call_queue::ConversationQueue::default()),
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        computer_admitted: test_admitted_computer_capabilities(),
        health: Arc::new(HealthState::default()),
        routes: Arc::new(RouteBindings::new()),
        browser: Arc::new(BrowserPlane::new()),
        browser_config: None,
        runtime_browser: None,
        sessions: browser_session::BrowserSessions::default(),
        user_browser: user_browser_bridge::UserBrowserBridge::new(),
        lease_clock: Arc::new(cerebellum_core::clock::SystemClock::new()),
        launch_service: None,
        management: test_management_plane(),
        consent: Arc::new(cingulate_client::desk::ConsentDesk::new(Arc::new(
            consent_drain::UnconfiguredCingulate,
        ))),
        consent_drain: Arc::new(consent_drain::ConsentDrain::default()),
        user_browser_cards: Arc::default(),
        #[cfg(test)]
        consent_test: None,
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        computer: Err(computer_capability::ComputerPlaneUnavailable::CaptureCustody),
        #[cfg(test)]
        route_test_handler: None,
        #[cfg(test)]
        cursor_for_test: None,
        #[cfg(all(test, target_os = "macos"))]
        computer_for_test: None,
        draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        drain_signal: Arc::new(tokio::sync::watch::channel(false).0),
        drain_notice: Arc::new(std::sync::OnceLock::new()),
        capture: login_capture::test_support::fixture().module,
        calls: Arc::new(journal::call_records::CallRecords::in_memory()),
        call_record_workers: Arc::new(CallRecordWorkers::default()),
        egress_deadlines: Arc::new(ConnectionDeadlines::default()),
        scopes: Arc::new(scope_watch::ScopeRevocation::default()),
    };
    planes.routes.insert(
        channel,
        epoch,
        AcceptedBindFacts::from_bind(
            &bind_identity_for_test(),
            session_caller_principal_for_test(),
            admission_facts,
            None,
            &subc_protocol::RouteTarget::ManagementSurface {
                module_id: "cerebellum".to_string(),
            },
        ),
    );
    planes
}

#[test]
fn parse_subc_arg_accepts_space_separated() {
    let args = vec!["--subc".to_string().into(), "/tmp/conn.json".into()];
    assert_eq!(
        parse_subc_arg(args).unwrap(),
        PathBuf::from("/tmp/conn.json")
    );
}

#[test]
fn parse_subc_arg_accepts_equals_form() {
    let args: Vec<OsString> = vec!["--subc=/tmp/conn.json".into()];
    assert_eq!(
        parse_subc_arg(args).unwrap(),
        PathBuf::from("/tmp/conn.json")
    );
}

#[test]
fn parse_subc_arg_rejects_missing_value() {
    let args: Vec<OsString> = vec!["--subc".into()];
    assert!(parse_subc_arg(args).is_err());
}

#[test]
fn parse_subc_arg_rejects_missing_flag() {
    let args: Vec<OsString> = vec!["--other".into()];
    assert!(parse_subc_arg(args).is_err());
}

#[test]
fn default_module_id_is_cerebellum() {
    assert_eq!(DEFAULT_MODULE_ID, "cerebellum");
}

#[test]
fn browser_status_is_the_single_capability() {
    assert_eq!(browser_session::BROWSER_STATUS, "browser.status");
}

#[test]
fn principal_backstop_rejects_unverified() {
    let trust = trust_for_principal(&Some(Principal::Unverified));
    assert!(!trust.is_first_party());
}

#[test]
fn principal_backstop_rejects_absent() {
    let trust = trust_for_principal(&None);
    assert!(!trust.is_first_party());
}

#[test]
fn principal_backstop_accepts_direct() {
    let trust = trust_for_principal(&Some(Principal::Direct));
    assert!(trust.is_first_party());
}

#[test]
fn principal_backstop_accepts_the_executive() {
    let trust = trust_for_principal(&Some(Principal::Reserved {
        module_id: "prefrontal".to_string(),
    }));
    assert!(trust.is_first_party());
}

#[test]
fn principal_backstop_rejects_subc_mcp() {
    let trust = trust_for_principal(&Some(Principal::Reserved {
        module_id: "subc-mcp".to_string(),
    }));
    assert!(!trust.is_first_party());
}

#[test]
fn malformed_canonical_declaration_set_never_reaches_manifest_filter() {
    let context = default_computer_context();
    let (mut declarations, _) = canonical_computer_declarations(&context);
    for declaration in &mut declarations {
        declaration.advertised = true;
    }
    declarations[0].capability_id = "computer.wait".to_string();
    let outcomes = COMPUTER_RELEASE_GATE_TABLE
        .iter()
        .filter(|gate| {
            !matches!(
                gate.source,
                ComputerReleaseGateSource::StruckSelfReferential { .. }
            )
        })
        .map(|gate| (gate.name, ComputerGateOutcome::Pass))
        .collect::<ComputerGateOutcomes>();
    assert!(advertised_computer_declarations(&declarations, &outcomes).is_empty());
}

#[test]
fn build_bindings_preserve_absence_and_bind_only_the_supplied_capture_review() {
    let inputs = release_inputs_from_build_bindings(BuildReleaseBindings {
        attendance_contract_owner: None,
        attendance_contract_revision: None,
        input_review_revision: None,
        global_dispatch_review_revision: None,
        capture_review_revision: Some("cerebellum-capture-review/v1@cb1f669"),
        semantic_actuation_review_revision: None,
        windows_actuation_review_revision: None,
        app_state_review_revision: None,
        element_addressed_review_revision: None,
        takeover_dispatch_review_revision: None,
        takeover_pointer_fronting_review_revision: None,
        app_use_fronting_review_revision: None,
        release_signing_topology_revision: None,
    });
    assert_eq!(
        inputs,
        ComputerReleaseInputs {
            attendance_contract_owner: None,
            attendance_contract_revision: None,
            input_review_revision: None,
            global_dispatch_review_revision: None,
            capture_review_revision: Some("cerebellum-capture-review/v1@cb1f669".to_string()),
            semantic_actuation_review_revision: None,
            windows_actuation_review_revision: None,
            app_state_review_revision: None,
            element_addressed_review_revision: None,
            takeover_dispatch_review_revision: None,
            takeover_pointer_fronting_review_revision: None,
            app_use_fronting_review_revision: None,
            release_signing_topology_revision: None,
            vocabulary_digests: computer::platform::VocabularyDigestInputs {
                manifest_digest: Some(
                    computer::platform::COMPUTER_ACTION_VOCABULARY_SHA256.to_string(),
                ),
                source_lock_digest: Some(
                    computer::platform::COMPUTER_ACTION_VOCABULARY_SHA256.to_string(),
                ),
                computed_artifact_digest: Some(
                    computer::platform::COMPUTER_ACTION_VOCABULARY_SHA256.to_string(),
                ),
            },
        }
    );
}

#[test]
fn struck_gates_remain_recorded_and_are_not_evaluated() {
    let struck: Vec<_> = COMPUTER_RELEASE_GATE_TABLE
        .iter()
        .filter_map(|gate| match gate.source {
            ComputerReleaseGateSource::StruckSelfReferential { reason } => {
                Some((gate.name, reason))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        struck.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
        vec![
            "computer_action_vocabulary_revision",
            "permission_matrix_revision",
            "capture_residual_leakage_revision",
            "process_identity_primitive_revision",
            "cerebellum_core_contract_revision",
            "c2_journal_pin_schema_id",
            "c2_journal_pin_revision",
            "attendance_contract_schema_id",
        ]
    );
    assert_eq!(
        struck[0].1,
        "The frozen artifact revision is independently validated by validate_vocabulary; this comparison only repeated an in-repository literal."
    );
    for (_, reason) in struck.iter().skip(1) {
        assert_eq!(
            *reason,
            "No production behavior reads this identifier; the former comparison repeated one in-repository literal and checked nothing."
        );
    }

    let context = ComputerCapabilityAdvertisementContext {
        inputs: release_inputs_from_build_bindings(BuildReleaseBindings {
            attendance_contract_owner: Some("fixture-attendance-owner"),
            attendance_contract_revision: Some("fixture-attendance-revision"),
            input_review_revision: Some("fixture-input-review"),
            global_dispatch_review_revision: Some("fixture-global-dispatch-review"),
            capture_review_revision: Some("fixture-capture-review"),
            semantic_actuation_review_revision: Some("fixture-semantic-actuation-review"),
            windows_actuation_review_revision: Some("fixture-windows-actuation-review"),
            app_state_review_revision: Some("fixture-app-state-review"),
            element_addressed_review_revision: Some("fixture-element-addressed-review"),
            takeover_dispatch_review_revision: Some("fixture-takeover-dispatch-review"),
            takeover_pointer_fronting_review_revision: Some("fixture-pointer-fronting-review"),
            app_use_fronting_review_revision: Some("fixture-app-use-fronting-review"),
            release_signing_topology_revision: Some("fixture-signing-topology"),
        }),
        permissions: Default::default(),
        startup: StartupCapabilityProbe::default(),
    };
    let outcomes = computer_gate_outcomes(&context);
    assert_eq!(
        outcomes.into_values().collect::<Vec<_>>(),
        vec![ComputerGateOutcome::Pass; 16]
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn fixed_input_hello_manifest_bytes_match_pre_inspection_builder() {
    let context = ComputerCapabilityAdvertisementContext {
        inputs: release_inputs_from_build_bindings(fully_bound_release_bindings()),
        permissions: Default::default(),
        startup: StartupCapabilityProbe::default(),
    };
    let provenance = subc_protocol::manifest::ManifestProvenance::new()
        .with_build_git_sha(Some("0123456789abcdef0123456789abcdef01234567".to_string()))
        .with_wire_crate_version(Some("0.32.4".to_string()));
    let value = compose_manifest(
        "manifest-fixture",
        &context,
        &BrowserSurface::NotConfigured,
        Some(provenance.clone()),
    );
    assert!(takeover_pointer_fronting_admitted(&context.inputs));
    let mut unbound_context = ComputerCapabilityAdvertisementContext {
        inputs: context.inputs.clone(),
        permissions: context.permissions.clone(),
        startup: context.startup.clone(),
    };
    unbound_context
        .inputs
        .takeover_pointer_fronting_review_revision = None;
    assert!(!takeover_pointer_fronting_admitted(&unbound_context.inputs));
    let unbound = compose_manifest(
        "manifest-fixture",
        &unbound_context,
        &BrowserSurface::NotConfigured,
        Some(provenance.clone()),
    );
    let digest = |manifest: &Value| manifest::sha256_hex(manifest.to_string().as_bytes());
    println!(
        "fixed HELLO bound={} unbound={}",
        digest(&value),
        digest(&unbound)
    );
    // Historical pins predate the flat press_key action. Remove only its
    // enum member, input property and mentions in the tool definition.
    let without_press_key = |mut previous: Value| {
        for role in previous["provides"].as_array_mut().unwrap() {
            if let Some(tools) = role.get_mut("tools").and_then(Value::as_array_mut) {
                for tool in tools
                    .iter_mut()
                    .filter(|tool| tool["name"] == "browser_use")
                {
                    crate::flat_tools::remove_press_key_definition(tool);
                }
            }
        }
        previous
    };
    let browser = BrowserSurface::Available(
        browser_config::parse_browser_config(include_str!(
            "../../tests/fixtures/legacy-macos-settings.jsonc"
        ))
        .unwrap()
        .unwrap(),
    );
    let configured = compose_manifest("manifest-fixture", &context, &browser, Some(provenance));
    let prior_configured = without_press_key(configured.clone());
    #[cfg(target_os = "linux")]
    let configured_pins = [
        "63b9befa57320ce343e87e90a302181c8dc95fe73374877d14e93db2208d68ff",
        "20d766513de57467a64377c89253525b142603bd15ca610a392f1518b77ac880",
    ];
    #[cfg(target_os = "macos")]
    let configured_pins = [
        "4809827b64d6d775e26c3c73115fc2bca98003594ce0d07210f31256a8009010",
        "79f982e516edc44da7144b9890aeed8f875ef40ac51b8c24e8df40f7e3758efd",
    ];
    assert_eq!(
        [digest(&prior_configured), digest(&configured)],
        configured_pins
    );
    // Historical bound manifests withheld click/drag before recovery was
    // measured. Subtract exactly their admission, including the selected
    // flat definition and release-evidence counts, without repinning history.
    let before_measurement = if cfg!(target_os = "macos") {
        let mut previous = without_press_key(agent_data::tests::without_agent_data(&value));
        let release = &mut previous["computer_plane_release"];
        let down = ["computer.takeover_click", "computer.takeover_drag"];
        for field in ["gate_admitted_capabilities", "advertised_capabilities"] {
            let rows = release[field].as_array_mut().unwrap();
            assert_eq!(rows.len(), 13);
            rows.retain(|row| !down.iter().any(|name| row == name));
            assert_eq!(rows.len(), 11);
        }
        assert_eq!(release["advertised_row_count"], 13);
        assert_eq!(release["scope"], "all_frozen_rows");
        release["advertised_row_count"] = json!(11);
        release["scope"] = json!("partial_runtime_advertisement");
        let names = release["advertised_capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| name.as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        let mut removed = 0;
        let mut replaced = 0;
        for role in previous["provides"].as_array_mut().unwrap() {
            if let Some(tools) = role.get_mut("tools").and_then(Value::as_array_mut) {
                let before = tools.len();
                tools.retain(|tool| !down.iter().any(|name| tool["name"] == *name));
                removed += before - tools.len();
                for tool in tools {
                    if tool["name"] == "computer_use" {
                        *tool = serde_json::to_value(flat_tools::computer_tool(&names).unwrap())
                            .unwrap();
                        replaced += 1;
                    }
                }
            }
        }
        assert_eq!((removed, replaced), (2, 1));
        assert_eq!(
            digest(&previous),
            "91a8d792d2688cbf7818e62aa989e11c02f1d70382c330eda12eec6b139d46ea"
        );
        previous
    } else {
        without_press_key(agent_data::tests::without_agent_data(&value))
    };
    // Subtract only display.read for comparisons with older manifests.
    // Every pre-existing operation and tool definition remains pinned.
    let without_display_read = |current: &Value| {
        let mut previous = current.clone();
        let mut removed = 0;
        for role in previous["provides"].as_array_mut().unwrap() {
            if let Some(operations) = role.get_mut("operations").and_then(Value::as_array_mut) {
                let before = operations.len();
                operations.retain(|operation| {
                    operation["name"] != cortexkit_role_tool_display::DISPLAY_READ
                });
                removed += before - operations.len();
            }
        }
        assert_eq!(removed, 1);
        previous
    };
    let before_read = without_display_read(&before_measurement);
    let before_read_unbound = without_display_read(&without_press_key(
        agent_data::tests::without_agent_data(&unbound),
    ));
    #[cfg(target_os = "linux")]
    let before_read_pins = [
        "7e31cf93aff05066e6057747b36fb780f6972b37c6eea61c67f5acd17a64289e",
        "5ccb6b3f6e8eb53cec1b5a5e6e572c43e376d0227b731c8271fb07ede73fa77a",
    ];
    #[cfg(target_os = "macos")]
    let before_read_pins = [
        "f1d836f66a286cc76034c0b43014c6b45ced89616182a58291839d113c1f6602",
        "c91f8cb9efa64fb61735541fcca446613e625d2151b95b27189ce43e65d17188",
    ];
    assert_eq!(
        [digest(&before_read), digest(&before_read_unbound)],
        before_read_pins
    );
    // Only the channel-support declaration may change the fixed HELLO.
    // Remove that exact addition and retain the complete previous pins.
    #[cfg(target_os = "linux")]
    let prior = [
        "8c7c3024e6b662373cdfc75cbd4af8bc36d60b39c96dd2b14b09267176cf2d4a",
        "5b43505f1804c63bdcdc220839f67f7a149ad7ce4832cd2c99d7776bc43e97d1",
    ];
    #[cfg(target_os = "macos")]
    let prior = [
        "ae5964cc14a0e7872cdb9833a2db31825639e0c2cea7bf979c3fb5e4bea283a2",
        "471542719ed51536d8f0c6e6795b0f5444a6102024222ea14e11b83b99bb386a",
    ];
    for (current, prior) in [&before_read, &before_read_unbound].into_iter().zip(prior) {
        let mut previous = current.clone();
        assert_eq!(
            previous
                .as_object_mut()
                .unwrap()
                .remove("registration_channel"),
            Some(json!(true))
        );
        assert_eq!(digest(&previous), prior);
    }

    // The unbound computer_use flat tool definition is byte-identical, but HELLO has
    // additive release evidence (and vocabulary/views differ elsewhere).
    // Normalize those HELLO additions only for historical comparison;
    // this is not a claim of raw HELLO byte equality.
    let mut legacy = before_read_unbound;
    assert_eq!(
        legacy
            .as_object_mut()
            .unwrap()
            .remove("registration_channel"),
        Some(json!(true))
    );
    let release = &mut legacy["computer_plane_release"];
    assert_eq!(release["frozen_row_count"], 13);
    assert_eq!(release["canonical_row_count"], 13);
    release["frozen_row_count"] = json!(12);
    release["canonical_row_count"] = json!(12);
    let missing =
        json!({"MissingExternalInput":{"gate":"takeover_pointer_fronting_review_revision"}});
    let outcomes = release["gate_outcomes"].as_array_mut().unwrap();
    assert_eq!(outcomes.len(), 16);
    let index = outcomes
        .iter()
        .position(|outcome| *outcome == missing)
        .expect("the unbound review is reported on HELLO");
    assert_eq!(outcomes.remove(index), missing);
    if release["advertised_row_count"] == 12 {
        assert_eq!(release["scope"], "partial_runtime_advertisement");
        release["scope"] = json!("all_frozen_rows");
    }
    // The personal-data abilities added five mapped capability tokens and
    // four management operations. Remove exactly those, so the historical
    // digests below still pin everything else.
    let ability_provides: Vec<String> = ability::manifest_capabilities().collect();
    let provides = legacy["capabilities"]["provides"].as_array_mut().unwrap();
    let before = provides.len();
    provides.retain(|name| !ability_provides.iter().any(|token| name == token.as_str()));
    assert_eq!(before - provides.len(), ability_provides.len());
    let mut removed_operations = 0;
    for role in legacy["provides"].as_array_mut().unwrap() {
        if let Some(operations) = role.get_mut("operations").and_then(Value::as_array_mut) {
            let before = operations.len();
            operations.retain(|operation| {
                !operation["name"]
                    .as_str()
                    .is_some_and(ability::is_operation)
            });
            removed_operations += before - operations.len();
        }
    }
    assert_eq!(removed_operations, 4);

    // Keep the historical view and no-project subtraction guards. The
    // normalization above must not hide any unrelated manifest change.
    let mut without_views = legacy.clone();
    without_views["capabilities"]["provides"]
        .as_array_mut()
        .unwrap()
        .retain(|name| name != cortexkit_role_tool_provider::TOOL_VIEWS_CAPABILITY);
    #[cfg(target_os = "linux")]
    let before_views = "f46b5ddc8c5b081adb40a3c2982d27822f9c7400bc62d189d74816a5eaa5d466";
    #[cfg(target_os = "macos")]
    let before_views = "b4839c9eee9e533d0aaf92dc4211a39bd379b1aa86b7bd927ad57c8b5f3df5c2";
    assert_eq!(digest(&without_views), before_views);
    #[cfg(target_os = "linux")]
    let previous = "76dbb08edce1bb7742f5efc2686b7e2ec42ad623586d16d91be1fbd52fa15662";
    #[cfg(target_os = "macos")]
    let previous = "808fb3381e8697e228ce49fb644a7116246b6691faf61d81fbafd6aa7a7af335";
    let mut predecessor = without_views;
    predecessor["capabilities"]["provides"]
        .as_array_mut()
        .unwrap()
        .retain(|name| name != subc_protocol::scope::BIND_NO_PROJECT_CAPABILITY);
    assert_eq!(digest(&predecessor), previous);
    #[cfg(target_os = "linux")]
    let before_pointer_fronting =
        "62fe03bb1a213e8c6d0c73000fca4de891118d5347440e35b96f8534a4c1fd51";
    #[cfg(target_os = "macos")]
    let before_pointer_fronting =
        "9e432098108c67566ea9e6502e98000a398f10fb7ff762ee3159b49d8c8e520d";
    assert_eq!(digest(&legacy), before_pointer_fronting);

    // Full HELLO pins include the internal move participant. Historical
    // comparisons above remove that role and capability, not tool definitions.
    #[cfg(target_os = "linux")]
    let expected = "5e4cf4f41c7b6fde17ee788a3f8250ed8e8ca25e1e32bdfbd6aad915f1249e45";
    #[cfg(target_os = "macos")]
    let expected = "817914f8a74d1ae1957976136eaca692c592226b50d5332accc4836136778d20";
    #[cfg(target_os = "linux")]
    let expected_unbound = "beddf7ef0765904a344b386bc49380d88187854fe5c8c341334970b9218ee1c3";
    #[cfg(target_os = "macos")]
    let expected_unbound = "4e38e12b36acc3830816c1ec886a6b23cf713e02ca1e009eb30cede5ed7ef7e0";
    assert_eq!(digest(&value), expected);
    assert_eq!(digest(&unbound), expected_unbound);
}

/// A daemon linking subc-protocol 0.32.11 must keep accepting this module's
/// HELLO. The 0.32.12 and 0.33 wire crates added two manifest maps
/// (`operation_payload`, `role_declarations`) that the older parser does
/// not know; both are left out of the encoding while empty. Declaring
/// either one would send HELLO bytes the older daemon was never tested
/// against, so the HELLO manifest, with and without a browser, carries
/// neither key.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn hello_manifest_declares_no_map_an_older_daemon_does_not_know() {
    let context = ComputerCapabilityAdvertisementContext {
        inputs: release_inputs_from_build_bindings(fully_bound_release_bindings()),
        permissions: Default::default(),
        startup: StartupCapabilityProbe::default(),
    };
    for surface in [
        BrowserSurface::NotConfigured,
        BrowserSurface::Available(browser_surface_config()),
    ] {
        // The same builder `send_hello` places in the HELLO body.
        let manifest =
            serialize_manifest_with_computer_plane_configured("cerebellum", &context, &surface);
        let keys: Vec<&String> = manifest.as_object().unwrap().keys().collect();
        assert!(keys.iter().any(|key| *key == "provides"), "{keys:?}");
        for newer in ["operation_payload", "role_declarations"] {
            assert!(
                !keys.iter().any(|key| *key == newer),
                "HELLO manifest declares `{newer}`: {keys:?}"
            );
        }
    }
}

/// Every external attestation bound, as a release build supplying all of
/// them would compile it.
#[test]
fn pointer_fronting_review_admits_measured_down_gestures_and_keeps_legacy_drag() {
    use std::collections::BTreeSet;
    let bound = release_inputs_from_build_bindings(fully_bound_release_bindings());
    let names = |inputs: ComputerReleaseInputs| {
        let context = ComputerCapabilityAdvertisementContext {
            inputs,
            permissions: Default::default(),
            startup: StartupCapabilityProbe::default(),
        };
        let mut declarations = computer::platform::capability_declarations(&context, true);
        for declaration in &mut declarations {
            declaration.advertised = true;
        }
        gate_admitted_computer_declarations(&declarations, &computer_gate_outcomes(&context))
            .into_iter()
            .map(|row| row.capability_id.clone())
            .collect::<Vec<_>>()
    };
    assert!(takeover_pointer_fronting_admitted(&bound));
    let bound_names = names(bound.clone());
    assert!(bound_names
        .iter()
        .any(|name| name == "computer.takeover_click"));
    assert!(bound_names
        .iter()
        .any(|name| name == "computer.takeover_drag"));
    assert!(bound_names
        .iter()
        .any(|name| name == "computer.takeover_move"));
    assert!(bound_names
        .iter()
        .any(|name| name == "computer.takeover_scroll"));
    let definition = flat_tools::computer_tool(&bound_names).unwrap();
    let bytes = serde_json::to_string(&definition).unwrap();
    assert!(
        bytes.len() <= 7_000,
        "bound definition is {} bytes",
        bytes.len()
    );
    assert!(bytes.contains("takeover_click"));
    assert!(bytes.contains("takeover_drag"));
    let mut legacy_names = bound_names.into_iter().collect::<BTreeSet<_>>();
    legacy_names.remove("computer.takeover_click");
    for absent in [
        None,
        Some(""),
        Some("placeholder"),
        Some("tbd"),
        Some("unknown"),
    ] {
        let mut inputs = bound.clone();
        inputs.takeover_pointer_fronting_review_revision = absent.map(str::to_owned);
        assert!(!takeover_pointer_fronting_admitted(&inputs));
        assert_eq!(
            names(inputs).into_iter().collect::<BTreeSet<_>>(),
            legacy_names
        );
    }
    assert_eq!(
        compiled_release_inputs()
            .takeover_pointer_fronting_review_revision
            .as_deref(),
        option_env!("CEREBELLUM_TAKEOVER_POINTER_FRONTING_REVIEW_REVISION")
    );
}

fn fully_bound_release_bindings() -> BuildReleaseBindings<'static> {
    BuildReleaseBindings {
        attendance_contract_owner: Some("fixture-attendance-owner"),
        attendance_contract_revision: Some("fixture-attendance-revision"),
        input_review_revision: Some("fixture-input-review"),
        global_dispatch_review_revision: Some("fixture-global-dispatch-review"),
        capture_review_revision: Some("fixture-capture-review"),
        semantic_actuation_review_revision: Some("fixture-semantic-actuation-review"),
        windows_actuation_review_revision: Some("fixture-windows-actuation-review"),
        app_state_review_revision: Some("fixture-app-state-review"),
        element_addressed_review_revision: Some("fixture-element-addressed-review"),
        takeover_dispatch_review_revision: Some("fixture-takeover-dispatch-review"),
        takeover_pointer_fronting_review_revision: Some("fixture-pointer-fronting-review"),
        app_use_fronting_review_revision: Some("fixture-app-use-fronting-review"),
        release_signing_topology_revision: Some("fixture-signing-topology"),
    }
}

/// The app-use review travels from its compile-time binding into the
/// release inputs, is reported by release evidence like every other
/// external attestation, and withholds no capability row when absent.
#[test]
fn app_use_fronting_review_is_reported_and_gates_no_row() {
    let bound = release_inputs_from_build_bindings(fully_bound_release_bindings());
    assert_eq!(
        bound.app_use_fronting_review_revision.as_deref(),
        Some("fixture-app-use-fronting-review")
    );
    let unbound = release_inputs_from_build_bindings(BuildReleaseBindings {
        app_use_fronting_review_revision: None,
        ..fully_bound_release_bindings()
    });
    assert_eq!(unbound.app_use_fronting_review_revision, None);

    let context = |inputs: ComputerReleaseInputs| ComputerCapabilityAdvertisementContext {
        inputs,
        permissions: Default::default(),
        startup: StartupCapabilityProbe::default(),
    };
    let bound = context(bound);
    let unbound = context(unbound);
    assert_eq!(
        computer_gate_outcomes(&bound).get("app_use_fronting_review_revision"),
        Some(&ComputerGateOutcome::Pass)
    );
    assert_eq!(
        computer_gate_outcomes(&unbound).get("app_use_fronting_review_revision"),
        Some(&ComputerGateOutcome::MissingExternalInput {
            gate: "app_use_fronting_review_revision".to_string(),
        })
    );

    // Every declaration is taken as advertised so that only the release
    // gate decides; the missing app-use review must withhold nothing.
    let admitted = |context: &ComputerCapabilityAdvertisementContext| {
        let mut declarations = computer::platform::capability_declarations(context, true);
        for declaration in &mut declarations {
            declaration.advertised = true;
        }
        let outcomes = computer_gate_outcomes(context);
        gate_admitted_computer_declarations(&declarations, &outcomes)
            .into_iter()
            .map(|declaration| declaration.capability_id.clone())
            .collect::<Vec<_>>()
    };
    let with_review = admitted(&bound);
    assert!(
        with_review.len() > 1,
        "the fully bound fixture must admit the reviewed rows: {with_review:?}"
    );
    assert_eq!(admitted(&unbound), with_review);
}

/// The places where this module brings an application forward or captures
/// a covered window, each named for the admission it needs.
#[derive(Debug, Clone, Copy)]
enum FrontingPath {
    ForegroundOneWayFront,
    NeedsFrontPress,
    ModifierChordUnderAppGrant,
    PersonSwitchRestoreSkip,
    HeldInputRestoreOrdering,
    KeystrokeBracketUnderTakeover,
    BringToFrontReadUnderTakeover,
    PreviewCapture,
}

const FRONTING_PATHS: [FrontingPath; 8] = [
    FrontingPath::ForegroundOneWayFront,
    FrontingPath::NeedsFrontPress,
    FrontingPath::ModifierChordUnderAppGrant,
    FrontingPath::PersonSwitchRestoreSkip,
    FrontingPath::HeldInputRestoreOrdering,
    FrontingPath::KeystrokeBracketUnderTakeover,
    FrontingPath::BringToFrontReadUnderTakeover,
    FrontingPath::PreviewCapture,
];

fn path_admitted(path: FrontingPath, inputs: &ComputerReleaseInputs) -> bool {
    match path {
        FrontingPath::ForegroundOneWayFront
        | FrontingPath::NeedsFrontPress
        | FrontingPath::ModifierChordUnderAppGrant
        | FrontingPath::PersonSwitchRestoreSkip
        | FrontingPath::HeldInputRestoreOrdering => app_use_fronting_admitted(inputs),
        FrontingPath::KeystrokeBracketUnderTakeover
        | FrontingPath::BringToFrontReadUnderTakeover => fronting_bracket_admitted(inputs),
        FrontingPath::PreviewCapture => preview_capture_admitted(inputs),
    }
}

/// Each combination of the takeover, capture and app-use reviews against
/// each fronting path and preview capture. The expected admissions are
/// written out per row rather than derived, so a change to either
/// predicate shows up as a named row. Every row is checked with valid and
/// with missing vocabulary digests, which must change nothing.
#[test]
fn each_attestation_combination_admits_exactly_its_fronting_paths() {
    // (takeover, capture, app use) bound ->
    // (app-use fronting paths, takeover bracket paths, preview capture)
    type Reviews = (bool, bool, bool);
    type Admissions = (bool, bool, bool);
    let table: [(Reviews, Admissions); 8] = [
        ((false, false, false), (false, false, false)),
        ((true, false, false), (false, true, false)),
        ((false, true, false), (false, false, false)),
        ((false, false, true), (false, false, false)),
        ((true, true, false), (false, true, false)),
        ((true, false, true), (true, true, false)),
        ((false, true, true), (false, false, true)),
        ((true, true, true), (true, true, true)),
    ];
    for ((takeover, capture, app_use), (app_use_paths, bracket_paths, preview)) in table {
        let base = fully_bound_release_bindings();
        let inputs = release_inputs_from_build_bindings(BuildReleaseBindings {
            takeover_dispatch_review_revision: base
                .takeover_dispatch_review_revision
                .filter(|_| takeover),
            capture_review_revision: base.capture_review_revision.filter(|_| capture),
            app_use_fronting_review_revision: base
                .app_use_fronting_review_revision
                .filter(|_| app_use),
            ..fully_bound_release_bindings()
        });
        let mut without_digests = inputs.clone();
        without_digests.vocabulary_digests = Default::default();
        for inputs in [&inputs, &without_digests] {
            for path in FRONTING_PATHS {
                let expected = match path {
                    FrontingPath::ForegroundOneWayFront
                    | FrontingPath::NeedsFrontPress
                    | FrontingPath::ModifierChordUnderAppGrant
                    | FrontingPath::PersonSwitchRestoreSkip
                    | FrontingPath::HeldInputRestoreOrdering => app_use_paths,
                    FrontingPath::KeystrokeBracketUnderTakeover
                    | FrontingPath::BringToFrontReadUnderTakeover => bracket_paths,
                    FrontingPath::PreviewCapture => preview,
                };
                assert_eq!(
                    path_admitted(path, inputs),
                    expected,
                    "{path:?} with takeover={takeover} capture={capture} \
                     app_use={app_use} digests={}",
                    inputs.vocabulary_digests.manifest_digest.is_some()
                );
            }
        }
    }
}

/// A stand-in value is not a review. The release gate reports it as an
/// implementation failure, and neither fronting outside the bracket nor
/// preview capture may treat it as bound.
#[test]
fn a_stand_in_app_use_review_admits_no_fronting_and_no_preview_capture() {
    for stand_in in ["placeholder", "tbd", "unknown", " "] {
        let inputs = release_inputs_from_build_bindings(BuildReleaseBindings {
            app_use_fronting_review_revision: Some(stand_in),
            ..fully_bound_release_bindings()
        });
        assert!(!app_use_fronting_admitted(&inputs), "{stand_in:?}");
        assert!(!preview_capture_admitted(&inputs), "{stand_in:?}");
        assert!(fronting_bracket_admitted(&inputs), "{stand_in:?}");
    }
}

/// The computer plane a module builds takes its app-use fronting and
/// preview-capture admissions from the release inputs compiled into this
/// binary, and from nothing else. A test build is compiled without the
/// release attestations, so here both must come out unadmitted; a plane
/// wired to admit either regardless of its release fails here.
#[cfg(any(target_os = "macos", target_os = "windows"))]
#[tokio::test]
async fn the_built_plane_admits_fronting_and_preview_capture_only_as_its_release_does() {
    let planes = Planes::new(Arc::new(HealthState::new()));
    let plane = planes
        .computer
        .as_ref()
        .unwrap_or_else(|_| panic!("an isolated module builds its computer plane"));
    let inputs = compiled_release_inputs();
    assert_eq!(
        plane.admits_app_use_fronting(),
        app_use_fronting_admitted(&inputs)
    );
    assert_eq!(
        plane.admits_preview_capture(),
        preview_capture_admitted(&inputs)
    );
}

/// The release gate itself holds the takeover rows to both reviews,
/// whatever the declaration says. Each review is left unbound in turn
/// through the attestation path while the declarations are taken as
/// advertised, so only the gate stands between the rows and the manifest.
#[test]
fn the_release_gate_holds_the_takeover_rows_to_both_reviews() {
    let bindings = |global: Option<&'static str>, takeover: Option<&'static str>| {
        ComputerCapabilityAdvertisementContext {
            inputs: release_inputs_from_build_bindings(BuildReleaseBindings {
                attendance_contract_owner: Some("fixture-attendance-owner"),
                attendance_contract_revision: Some("fixture-attendance-revision"),
                input_review_revision: Some("fixture-input-review"),
                global_dispatch_review_revision: global,
                capture_review_revision: Some("fixture-capture-review"),
                semantic_actuation_review_revision: Some("fixture-semantic-actuation-review"),
                windows_actuation_review_revision: Some("fixture-windows-actuation-review"),
                app_state_review_revision: Some("fixture-app-state-review"),
                element_addressed_review_revision: Some("fixture-element-addressed-review"),
                takeover_dispatch_review_revision: takeover,
                takeover_pointer_fronting_review_revision: Some("fixture-pointer-review"),
                app_use_fronting_review_revision: Some("fixture-app-use-fronting-review"),
                release_signing_topology_revision: Some("fixture-signing-topology"),
            }),
            permissions: Default::default(),
            startup: StartupCapabilityProbe::default(),
        }
    };
    let takeover_rows = [
        "computer.takeover_move",
        "computer.takeover_click",
        "computer.takeover_drag",
        "computer.takeover_scroll",
    ];
    let admitted = |context: &ComputerCapabilityAdvertisementContext| {
        let mut declarations = computer::platform::capability_declarations(context, true);
        for declaration in &mut declarations {
            declaration.advertised = true;
        }
        let outcomes = computer_gate_outcomes(context);
        gate_admitted_computer_declarations(&declarations, &outcomes)
            .into_iter()
            .map(|declaration| declaration.capability_id.clone())
            .collect::<Vec<_>>()
    };

    let both = admitted(&bindings(Some("fixture-global"), Some("fixture-takeover")));
    // With both reviews bound and mouse-up recovery measured, every
    // takeover row is admitted, the button-down rows included.
    for row in takeover_rows {
        assert!(both.iter().any(|id| id == row), "{row}: {both:?}");
    }
    for (gate, context) in [
        (
            "global_dispatch_review_revision",
            bindings(None, Some("fixture-takeover")),
        ),
        (
            "takeover_dispatch_review_revision",
            bindings(Some("fixture-global"), None),
        ),
    ] {
        assert_eq!(
            computer_gate_outcomes(&context).get(gate),
            Some(&ComputerGateOutcome::MissingExternalInput {
                gate: gate.to_string()
            })
        );
        let admitted = admitted(&context);
        for row in takeover_rows {
            assert!(!admitted.iter().any(|id| id == row), "{gate}: {row}");
        }
        assert!(
            admitted.iter().any(|id| id == "computer.type"),
            "{gate} withheld a row it does not govern: {admitted:?}"
        );
    }
}
