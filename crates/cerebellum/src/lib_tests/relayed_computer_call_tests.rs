use super::*;
use crate::test_support::HANG_GUARD;
use cerebellum_computer::app_state::source::{
    AppStateReadError, AppStateSource, RawAppState, ReadBounds,
};
use cerebellum_computer::capture_custody::{
    CaptureCustody, CustodyBounds, InMemoryCustodyStorage, InMemoryGrantAuthority,
};
use cerebellum_computer::platform::{ProcessGrant, TargetResolution};
use cerebellum_core::journal::{
    CallOriginRecord, InMemoryJournalStorage, JournalConfig, JournalStorage, OriginCarrier,
};

const CHANNEL: u16 = 7;
const EPOCH: u32 = 1;
const APP: &str = "com.example.Editor";

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

/// An application whose state cannot be read. The plane journals such a
/// read before it answers, so the call writes a row without touching a
/// real application.
struct Unreadable;

impl AppStateSource for Unreadable {
    fn read_app_state(
        &self,
        _target: &ProcessGrant,
        _bounds: ReadBounds,
    ) -> Result<RawAppState, AppStateReadError> {
        Err(AppStateReadError::Unreadable)
    }
}

/// Planes whose computer journal is held in `storage`, in memory, with one
/// tool route for the session caller that can relay a question.
fn planes(storage: &InMemoryJournalStorage) -> Planes {
    planes_with_source(storage, Arc::new(Unreadable))
}

fn planes_with_source(storage: &InMemoryJournalStorage, source: Arc<dyn AppStateSource>) -> Planes {
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::default()),
        None,
        JournalPersistence::Isolated,
    );
    planes.management = Arc::new(ManagementPlane::new(Arc::new(Running)));
    let custody = CaptureCustody::new(
        CustodyBounds {
            maximum_verification_duration_ms: 5_000,
            maximum_pin_lifetime_ms: 30_000,
            maximum_concurrently_pinned_artifacts: 8,
            maximum_total_pinned_artifact_bytes: 64 * 1024 * 1024,
            maximum_custody_attachment_bytes: 16 * 1024 * 1024,
        },
        InMemoryGrantAuthority::default(),
        InMemoryCustodyStorage::new(),
    )
    .unwrap();
    let audit = cerebellum_computer::audit::ComputerAudit::new(
        cerebellum_computer::audit::redaction::ExcludeApplicationText,
        cerebellum_computer::platform::severity::load_severity_taxonomy().unwrap(),
        JournalConfig {
            journal_retention_bytes: 8 * 1024 * 1024,
            journal_max_entry_bytes: 64 * 1024,
        },
        PlaneJournalStorage::InMemory(storage.clone()),
        custody,
    )
    .unwrap();
    // The screen is pinned unlocked: a locked developer machine would
    // refuse the call before it reads anything.
    planes.computer = Ok(Arc::new(
        computer_capability::ComputerPlane::with_synthetic_driver(audit, || {
            computer_capability::NativeComputerPlatformDriver::default()
                .without_expected_post_condition()
        })
        .with_permission_liveness(computer_capability::live_for_test())
        .with_session_lock_for_test(Some(false))
        .with_app_state_source(source),
    ));
    planes.computer_admitted = Arc::new(["computer.read_state".to_string()].into());
    planes.routes.insert(
        CHANNEL,
        EPOCH,
        AcceptedBindFacts::from_bind(
            &subc_protocol::BindIdentity::new("test", "test-session".to_string()),
            session_caller_principal_for_test(),
            Some(&json!({
                "agentProjectId": "test-project",
                "sessionKind": "primary",
                "effectiveCapabilityScope": ["*"],
            })),
            Some(&["elicitation".to_string()]),
            &subc_protocol::RouteTarget::ToolProvider {
                module_id: "cerebellum".to_string(),
            },
        ),
    );
    computer_grants::tests::CardService::install(planes, CHANNEL, EPOCH)
}

/// Send one `computer_use` read of the application, allow the app when
/// the call asks, and return the computer journal's decoded entries.
async fn read_state_rows(origin: Option<Value>) -> Vec<Value> {
    let storage = InMemoryJournalStorage::new();
    let planes = planes(&storage);
    let mut request = json!({
        "name": flat_tools::COMPUTER_USE,
        "arguments": {"action": "read_state", "target": APP},
    });
    if let Some(origin) = origin {
        request["origin"] = origin;
    }
    let (tx, mut rx) = mpsc::channel(8);
    handle_frame(
        Frame::build(
            FrameType::Request,
            control_flags(),
            CHANNEL,
            EPOCH,
            42,
            serde_json::to_vec(&request).unwrap(),
        )
        .unwrap(),
        &tx,
        &planes,
    )
    .await
    .unwrap();
    let question = planes
        .consent_test
        .as_ref()
        .unwrap()
        .card(CHANNEL, EPOCH)
        .await;
    assert!(planes.consent_test.as_ref().unwrap().answer(
        question.header.corr,
        cingulate_client::ScriptedAnswer::Answered(json!({"decision":"allow_30m"}))
    ));
    let frame = tokio::time::timeout(HANG_GUARD, rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        frame.header.ty,
        FrameType::Response,
        "{}",
        String::from_utf8_lossy(&frame.body)
    );
    assert_eq!(frame.header.corr, 42);

    let state = serde_json::to_value(storage.load().unwrap()).unwrap();
    state["entries"]
        .as_object()
        .into_iter()
        .flat_map(|entries| entries.values())
        .map(|entry| {
            let bytes =
                cerebellum_core::serde_base64::decode(entry["bytes"].as_str().unwrap()).unwrap();
            serde_json::from_slice(&bytes).unwrap()
        })
        .collect()
}

async fn bind_basal_flow(
    planes: &Planes,
    tx: &mpsc::Sender<Frame>,
    rx: &mut mpsc::Receiver<Frame>,
) {
    bind_basal_flow_target(
        planes,
        tx,
        rx,
        subc_protocol::RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
    )
    .await;
}

async fn bind_basal_flow_target(
    planes: &Planes,
    tx: &mpsc::Sender<Frame>,
    rx: &mut mpsc::Receiver<Frame>,
    target: subc_protocol::RouteTarget,
) {
    let stamp = subc_protocol::scope::ScopeStamp::new(
        session_caller_principal_for_test().unwrap(),
        "flow-head",
        1,
        subc_protocol::scope::ScopeKind::Head,
    )
    .with_attributes(
        subc_protocol::scope::ScopeAttributes::new()
            .with_agent_id(Some("test-project".into()))
            .with_delegates(true)
            .with_flow_id(Some("flow-computer".into())),
    )
    .with_owner_authorized(true);
    let bind = subc_protocol::session::ModuleControlRequest::RouteBind {
        role_versions: None,
        call_mode: None,
        route_channel: CHANNEL,
        epoch: EPOCH,
        target,
        identity: subc_protocol::BindIdentity::new("test", "test-session"),
        principal: Some(subc_protocol::Principal::Reserved {
            module_id: "basal".into(),
        }),
        consumer_capabilities: Some(vec!["elicitation".into()]),
        admission_facts: None,
        scope: Some(stamp),
    };
    handle_frame(
        Frame::build(
            FrameType::Request,
            control_flags(),
            0,
            0,
            40,
            serde_json::to_vec(&bind).unwrap(),
        )
        .unwrap(),
        tx,
        planes,
    )
    .await
    .unwrap();
    let reply = rx.recv().await.unwrap();
    assert_eq!(
        reply.header.ty,
        FrameType::Response,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
}

#[tokio::test]
async fn flow_persistent_app_grant_reads_and_missing_grant_never_reads() {
    use computer_grants::{
        AlwaysGrantRecord, ComputerGrants, GrantStorage, GrantStoreState, InMemoryGrantStorage,
        GRANT_STORE_VERSION,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct CountReads(Arc<AtomicUsize>);
    impl AppStateSource for CountReads {
        fn read_app_state(
            &self,
            _: &ProcessGrant,
            _: ReadBounds,
        ) -> Result<RawAppState, AppStateReadError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(AppStateReadError::Unreadable)
        }
    }
    for granted in [false, true] {
        let reads = Arc::new(AtomicUsize::new(0));
        let audit_storage = InMemoryJournalStorage::new();
        let mut planes = planes_with_source(&audit_storage, Arc::new(CountReads(reads.clone())));
        let storage = Arc::new(InMemoryGrantStorage::new());
        storage
            .save(&GrantStoreState {
                version: GRANT_STORE_VERSION,
                records: if granted {
                    vec![AlwaysGrantRecord {
                        agent_project_id: "test-project".into(),
                        bundle_identity: APP.into(),
                        team_id: Some("FIXTURE001".into()),
                        designated_requirement: Some(
                            "certificate leaf[subject.OU] = \"FIXTURE001\"".into(),
                        ),
                        machine_uuid: "machine".into(),
                        created_at_ms: 1,
                    }]
                } else {
                    vec![]
                },
            })
            .unwrap();
        planes.management = Arc::new(ManagementPlane::with_computer_grants(
            Arc::new(Running),
            Arc::new(ComputerGrants::open(
                storage.clone(),
                Some("machine".into()),
            )),
        ));
        // A grant given in this conversation must not authorize the flow;
        // only the owner's persistent app grant may.
        planes
            .management
            .computer_grants()
            .seed_conversation_app_for_test("test-session", APP);
        planes.computer_admitted =
            Arc::new(["computer.read_state".into(), "computer.keys".into()].into());
        let (tx, mut rx) = mpsc::channel(8);
        bind_basal_flow(&planes, &tx, &mut rx).await;
        let request =
            json!({"name":"computer_use","arguments":{"action":"read_state","target":APP}});
        handle_frame(
            Frame::build(
                FrameType::Request,
                control_flags(),
                CHANNEL,
                EPOCH,
                42,
                serde_json::to_vec(&request).unwrap(),
            )
            .unwrap(),
            &tx,
            &planes,
        )
        .await
        .unwrap();
        let reply = tokio::time::timeout(HANG_GUARD, rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply.header.ty, FrameType::Response);
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        if granted {
            assert_eq!(reads.load(Ordering::SeqCst), 1, "{body}");
        } else {
            assert_eq!(body["outcome"], "consent_unavailable", "{body}");
            assert_eq!(body["reason"], "unattended_flow");
            assert_eq!(reads.load(Ordering::SeqCst), 0);
            let token = body["detail"]["grant"].as_str().unwrap();
            let label = body["detail"]["grant_label"].as_str().unwrap();
            let decoded = management::decode_grant(token).unwrap();
            assert_eq!(
                decoded,
                json!({"tool":"computer_use","target":APP,"signer":"certificate leaf[subject.OU] = \"FIXTURE001\"","level":4})
            );
            assert!(label.starts_with("control of "));
            bind_basal_flow_target(
                &planes,
                &tx,
                &mut rx,
                subc_protocol::RouteTarget::ManagementSurface {
                    module_id: "cerebellum".into(),
                },
            )
            .await;
            let query = json!({"method":management::WOULD_ASK,"params":{"agent_id":"test-project","flow_id":"flow-computer","items":[{"grant":token}]}});
            for restored in [false, true] {
                if restored {
                    storage
                        .save(&GrantStoreState {
                            version: GRANT_STORE_VERSION,
                            records: vec![AlwaysGrantRecord {
                                agent_project_id: "test-project".into(),
                                bundle_identity: APP.into(),
                                team_id: Some("FIXTURE001".into()),
                                designated_requirement: Some(
                                    "certificate leaf[subject.OU] = \"FIXTURE001\"".into(),
                                ),
                                machine_uuid: "machine".into(),
                                created_at_ms: 1,
                            }],
                        })
                        .unwrap();
                    planes.management = Arc::new(ManagementPlane::with_computer_grants(
                        Arc::new(Running),
                        Arc::new(ComputerGrants::open(
                            storage.clone(),
                            Some("machine".into()),
                        )),
                    ));
                }
                handle_frame(
                    Frame::build(
                        FrameType::Request,
                        control_flags(),
                        CHANNEL,
                        EPOCH,
                        90,
                        serde_json::to_vec(&query).unwrap(),
                    )
                    .unwrap(),
                    &tx,
                    &planes,
                )
                .await
                .unwrap();
                let answer = rx.recv().await.unwrap();
                assert_eq!(answer.header.ty, FrameType::Response);
                let answer: Value = serde_json::from_slice(&answer.body).unwrap();
                assert_eq!(
                    answer["items"][0]["verdict"],
                    if restored { "yes" } else { "would_ask" },
                    "{answer}"
                );
            }
            let mut wrong_signer = decoded.clone();
            wrong_signer["signer"] = json!("another signer");
            let mut wrong_query = query.clone();
            wrong_query["params"]["items"][0]["grant"] =
                json!(management::encode_grant(wrong_signer));
            handle_frame(
                Frame::build(
                    FrameType::Request,
                    control_flags(),
                    CHANNEL,
                    EPOCH,
                    91,
                    serde_json::to_vec(&wrong_query).unwrap(),
                )
                .unwrap(),
                &tx,
                &planes,
            )
            .await
            .unwrap();
            let answer: Value = serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
            assert_eq!(answer["items"][0]["verdict"], "would_ask", "{answer}");
            let journal = planes.browser.journal_export_for_test().await;
            assert!(!journal.is_empty());
            assert!(!journal.contains(token));
            assert!(!journal.contains(label));
            let audit = serde_json::to_value(audit_storage.load().unwrap()).unwrap();
            assert!(
                audit["entries"].as_object().unwrap().is_empty(),
                "a refused computer action must not create an action journal record"
            );
        }
        assert_no_card_raised(&planes);
        assert!(rx.try_recv().is_err());
        if granted {
            planes
                .management
                .computer_grants()
                .seed_takeover_for_test("test-project");
            let keys = json!({"name":"computer_use","arguments":{"action":"keys","target":APP,"keys":["command","s"]}});
            handle_frame(
                Frame::build(
                    FrameType::Request,
                    control_flags(),
                    CHANNEL,
                    EPOCH,
                    43,
                    serde_json::to_vec(&keys).unwrap(),
                )
                .unwrap(),
                &tx,
                &planes,
            )
            .await
            .unwrap();
            let reply = tokio::time::timeout(HANG_GUARD, rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply.header.ty, FrameType::Response);
            let body: Value = serde_json::from_slice(&reply.body).unwrap();
            assert_eq!(body["outcome"], "consent_unavailable", "{body}");
            assert_eq!(body["reason"], "takeover_not_for_flows", "{body}");
            assert_eq!(
                reads.load(Ordering::SeqCst),
                1,
                "fronting keys must refuse before another app read"
            );
            assert_no_card_raised(&planes);
            assert!(rx.try_recv().is_err());
        }
    }
}

#[tokio::test]
async fn flow_takeover_refuses_even_with_existing_takeover_grant() {
    let mut planes = planes(&InMemoryJournalStorage::new());
    planes.computer_admitted = Arc::new(
        [
            "computer.takeover_move".into(),
            "computer.takeover_click".into(),
            "computer.takeover_drag".into(),
            "computer.takeover_scroll".into(),
        ]
        .into(),
    );
    let (tx, mut rx) = mpsc::channel(8);
    bind_basal_flow(&planes, &tx, &mut rx).await;
    planes
        .management
        .computer_grants()
        .seed_takeover_for_test("test-project");
    let image_id = planes.management.app_state_sessions().register_image(
        "test-session",
        cerebellum_computer::app_state::session::RegisteredImage {
            bundle_identity: APP.into(),
            pid: 4242,
            process_generation: "1700000000000000".into(),
            width_px: 100,
            height_px: 100,
            mapping: cerebellum_computer::app_state::image::ImageMapping::for_window(
                (0.0, 0.0),
                (100.0, 100.0),
                (100, 100),
                (100, 100),
            )
            .unwrap(),
        },
    );
    for (corr, action) in [
        (
            45,
            json!({"action":"takeover_click", "image_id":image_id, "x":1,"y":1}),
        ),
        (
            44,
            json!({"action":"takeover_scroll", "target":APP,"axis":"vertical","amount_lines":1}),
        ),
        (
            42,
            json!({"action":"takeover_move", "image_id":image_id, "to":{"x":1,"y":1}}),
        ),
        (
            43,
            json!({"action":"takeover_drag", "image_id":image_id, "from":{"x":1,"y":1},"to":{"x":2,"y":2}}),
        ),
    ] {
        let request = json!({"name":"computer_use","arguments":action});
        handle_frame(
            Frame::build(
                FrameType::Request,
                control_flags(),
                CHANNEL,
                EPOCH,
                corr,
                serde_json::to_vec(&request).unwrap(),
            )
            .unwrap(),
            &tx,
            &planes,
        )
        .await
        .unwrap();
        let reply = tokio::time::timeout(HANG_GUARD, rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply.header.ty, FrameType::Response);
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(body["outcome"], "consent_unavailable", "{body}");
        assert_eq!(body["detail"]["reason"], "takeover_not_for_flows", "{body}");
        assert_no_card_raised(&planes);
        assert!(rx.try_recv().is_err());
    }
}

#[tokio::test]
async fn flow_scope_admission_blocks_computer_reads_before_consent() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct CountReads(Arc<AtomicUsize>);
    impl AppStateSource for CountReads {
        fn read_app_state(
            &self,
            _: &ProcessGrant,
            _: ReadBounds,
        ) -> Result<RawAppState, AppStateReadError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(AppStateReadError::Unreadable)
        }
    }
    let reads = Arc::new(AtomicUsize::new(0));
    let storage = InMemoryJournalStorage::new();
    let planes = planes_with_source(&storage, Arc::new(CountReads(reads.clone())));
    let (tx, mut rx) = mpsc::channel(8);
    for flow_id in [Some("flow-1".to_string()), None] {
        let stamp = subc_protocol::scope::ScopeStamp::new(
            session_caller_principal_for_test().unwrap(),
            "head",
            1,
            subc_protocol::scope::ScopeKind::Head,
        )
        .with_attributes(
            subc_protocol::scope::ScopeAttributes::new()
                .with_agent_id(Some("test-project".into()))
                .with_delegates(true)
                .with_flow_id(flow_id.clone()),
        )
        .with_owner_authorized(true);
        let bind = subc_protocol::session::ModuleControlRequest::RouteBind {
            role_versions: None,
            call_mode: None,
            route_channel: CHANNEL,
            epoch: EPOCH,
            target: subc_protocol::RouteTarget::ToolProvider {
                module_id: "cerebellum".into(),
            },
            identity: subc_protocol::BindIdentity::new("test", "test-session"),
            principal: session_caller_principal_for_test(),
            consumer_capabilities: Some(vec!["elicitation".into()]),
            admission_facts: Some(
                json!({"agentProjectId":"test-project", "sessionKind":"primary"}),
            ),
            scope: Some(stamp),
        };
        handle_frame(
            Frame::build(
                FrameType::Request,
                control_flags(),
                0,
                0,
                40,
                serde_json::to_vec(&bind).unwrap(),
            )
            .unwrap(),
            &tx,
            &planes,
        )
        .await
        .unwrap();
        assert_eq!(rx.recv().await.unwrap().header.ty, FrameType::Response);
        let request =
            json!({"name":"computer_use", "arguments":{"action":"read_state", "target":APP}});
        handle_frame(
            Frame::build(
                FrameType::Request,
                control_flags(),
                CHANNEL,
                EPOCH,
                42,
                serde_json::to_vec(&request).unwrap(),
            )
            .unwrap(),
            &tx,
            &planes,
        )
        .await
        .unwrap();
        let mut reply = if flow_id.is_some() {
            tokio::time::timeout(HANG_GUARD, rx.recv())
                .await
                .unwrap()
                .unwrap()
        } else {
            planes
                .consent_test
                .as_ref()
                .unwrap()
                .card(CHANNEL, EPOCH)
                .await
        };
        if flow_id.is_some() {
            assert_eq!(reply.header.ty, FrameType::Response);
            assert_eq!(
                serde_json::from_slice::<Value>(&reply.body).unwrap(),
                json!({
                    "outcome":"consent_unavailable", "detail":{"reason":"flow_carrier_not_admitted"}, "remedy":"open the flow route through authorized reserved:basal"
                })
            );
            assert_eq!(reads.load(Ordering::SeqCst), 0);
            assert_no_card_raised(&planes);
            assert!(
                rx.try_recv().is_err(),
                "a flow must not send an elicitation"
            );
        } else {
            assert_eq!(
                reply.header.ty,
                FrameType::Request,
                "the attended route may ask for app consent"
            );
            assert!(planes.consent_test.as_ref().unwrap().answer(
                reply.header.corr,
                cingulate_client::ScriptedAnswer::Answered(json!({"decision":"allow_30m"})),
            ));
            reply = tokio::time::timeout(HANG_GUARD, rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply.header.ty, FrameType::Response);
            assert_eq!(
                reads.load(Ordering::SeqCst),
                1,
                "the non-flow route actually reads synthetic app state"
            );
        }
    }
}

#[tokio::test]
async fn a_relayed_computer_call_names_its_origin_on_its_journal_row() {
    let rows = read_state_rows(Some(json!({
        "carrier": {"kind": "reserved", "module_id": "agent-host"},
        "call_key": "agent:read-1",
    })))
    .await;
    assert!(!rows.is_empty(), "the read wrote no journal row");
    let expected = serde_json::to_value(CallOriginRecord::Relayed {
        carrier: OriginCarrier::Reserved {
            module_id: "agent-host".to_string(),
        },
        call_key: "agent:read-1".to_string(),
    })
    .unwrap();
    for row in &rows {
        assert_eq!(row["codec_version"], "ck-computer-journal/v3", "{row}");
        assert_eq!(row["identity"]["origin"], expected, "{row}");
        // Still the route's own principal: the origin names who it acted
        // for, never who acted.
        assert!(
            row["identity"]["principal"]
                .as_str()
                .is_some_and(|principal| principal.contains("prefrontal-core")),
            "{row}"
        );
    }
}

#[tokio::test]
async fn a_computer_call_naming_no_origin_writes_none_on_its_journal_row() {
    let rows = read_state_rows(None).await;
    assert!(!rows.is_empty(), "the read wrote no journal row");
    for row in &rows {
        assert!(row["identity"].get("origin").is_none(), "{row}");
    }
}
