use cerebellum_computer::platform::{
    capability_declarations, CapabilityAdvertisementContext, ImmutableReleaseInputs,
    PermissionLiveness, PermissionLivenessReport, PermissionProbeResult, PermissionService,
    StartupCapabilityProbe, VocabularyDigestInputs, COMPUTER_ACTION_VOCABULARY_SHA256,
};

fn readings(state: PermissionLiveness) -> PermissionLivenessReport {
    PermissionLivenessReport::from_results(
        [
            PermissionService::Accessibility,
            PermissionService::ScreenRecording,
            PermissionService::InputMonitoring,
            PermissionService::PostEvent,
        ]
        .into_iter()
        .map(|service| PermissionProbeResult {
            service,
            liveness: state,
            responsible_process: "ck-cerebellum".into(),
            off_main: true,
        }),
    )
}

fn context(state: PermissionLiveness) -> CapabilityAdvertisementContext {
    let pin = Some("fixture-review-v1".to_string());
    let digest = Some(COMPUTER_ACTION_VOCABULARY_SHA256.to_string());
    CapabilityAdvertisementContext {
        inputs: ImmutableReleaseInputs {
            takeover_pointer_fronting_review_revision: None,
            attendance_contract_owner: pin.clone(),
            attendance_contract_revision: pin.clone(),
            input_review_revision: pin.clone(),
            global_dispatch_review_revision: pin.clone(),
            capture_review_revision: pin.clone(),
            semantic_actuation_review_revision: pin.clone(),
            app_state_review_revision: pin.clone(),
            element_addressed_review_revision: pin.clone(),
            takeover_dispatch_review_revision: pin.clone(),
            app_use_fronting_review_revision: pin.clone(),
            windows_actuation_review_revision: pin.clone(),
            release_signing_topology_revision: pin,
            vocabulary_digests: VocabularyDigestInputs {
                manifest_digest: digest.clone(),
                source_lock_digest: digest.clone(),
                computed_artifact_digest: digest,
            },
        },
        permissions: readings(state),
        startup: StartupCapabilityProbe {
            permissions: readings(state),
            ..Default::default()
        },
    }
}

/// Compare the tool definitions in the HELLO message the module sends the daemon,
/// including the configured browser surface. Compare serialized definitions, not
/// just action membership: descriptions and every schema property are prompt-cache
/// inputs too.
#[test]
fn permission_states_never_change_serialized_tool_definitions() {
    let browser = crate::BrowserSurface::Available(crate::BrowserConfig {
        executable_path: None,
        expected_identity: None,
        launch_handshake_deadline_ms: 100,
        termination_grace_period_ms: 100,
        browser_idle_timeout_ms: 30_000,
        browser_exit_observation_deadline_ms: 100,
        navigation_settle_deadline_ms: 100,
    });
    let definitions = |state| {
        let manifest = crate::serialize_manifest_with_computer_plane_configured(
            "cerebellum",
            &context(state),
            &browser,
        );
        let tools = manifest["provides"][0]["tools"].as_array().unwrap();
        // A missing tool is compared as absent rather than unwrapped: where no app
        // identity reader exists, `computer_use` is absent in every state, and
        // that absence must also not vary with permissions.
        ["computer_use", "browser_use"].map(|name| {
            tools
                .iter()
                .find(|tool| tool["name"] == name)
                .map(|tool| serde_json::to_vec(tool).unwrap())
        })
    };
    let live = definitions(PermissionLiveness::Live);
    assert!(live[1].is_some(), "browser_use must be offered");
    assert_eq!(
        live[0].is_some(),
        cfg!(target_os = "macos"),
        "computer_use is offered exactly where app grants can be minted"
    );
    // Also build declarations with platform support enabled on every host. On
    // non-macOS hosts, the HELLO message the module sends the daemon offers no
    // computer plane at all, leaving every row untested there.
    let live_declarations = capability_declarations(&context(PermissionLiveness::Live), true);
    assert_eq!(
        live_declarations
            .iter()
            .filter(|row| row.advertised)
            .count(),
        12
    );
    for state in [
        PermissionLiveness::Unavailable,
        PermissionLiveness::GrantedPendingRelaunch,
        PermissionLiveness::Unresolved,
        PermissionLiveness::ProbeFailed,
    ] {
        assert_eq!(
            live,
            definitions(state),
            "flat tool definitions changed for {state:?}"
        );
        assert_eq!(
            live_declarations,
            capability_declarations(&context(state), true),
            "granular declarations changed for {state:?}"
        );
    }
}

#[cfg(target_os = "macos")]
mod wire {
    use super::*;
    use crate::computer_capability::permissions::live_for_test;
    use crate::test_support::HANG_GUARD;
    use cerebellum_computer::platform::TargetResolution;
    use serde_json::{json, Value};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use subc_protocol::{Frame, FrameType};

    struct NothingRuns(Arc<AtomicUsize>);
    impl crate::management::TargetResolver for NothingRuns {
        fn resolve(&self, _bundle_identity: &str) -> TargetResolution {
            self.0.fetch_add(1, Ordering::SeqCst);
            TargetResolution::NotRunning
        }
    }

    async fn call(name: &str, action: &str, report: PermissionLivenessReport) -> (Value, usize) {
        let mut planes = crate::Planes::with_browser_config_journaling(
            Arc::new(cerebellum_core::health::HealthState::default()),
            None,
            crate::JournalPersistence::Isolated,
        );
        let lookups = Arc::new(AtomicUsize::new(0));
        planes.management = Arc::new(crate::management::ManagementPlane::new(Arc::new(
            NothingRuns(lookups.clone()),
        )));
        planes.computer =
            super::super::computer_audit(crate::JournalPersistence::Isolated).map(|audit| {
                Arc::new(
                    super::super::ComputerPlane::with_synthetic_driver_and_result_schema_enforcement(audit, super::super::ResultSchemaEnforcement::Withhold, || {
                        panic!("permission refusal must not construct a dispatch driver")
                    })
                    .with_permission_liveness(report)
                    .with_session_lock_for_test(Some(false)),
                )
            });
        // Missing-permission calls must be advertised before they can return a
        // permission refusal. Build the admitted set with the production
        // advertisement function rather than installing a test-only list.
        planes.computer_admitted = Arc::new(
            crate::computer_release_evidence(&context(PermissionLiveness::Unavailable))
                .gate_admitted_capabilities
                .into_iter()
                .collect(),
        );
        planes.routes.insert(
            7,
            1,
            crate::AcceptedBindFacts::from_bind(
                &subc_protocol::BindIdentity::new("test", "session".to_string()),
                crate::session_caller_principal_for_test(),
                Some(
                    &json!({"agentProjectId":"test-project", "sessionKind":"primary",
                "effectiveCapabilityScope":["*"]}),
                ),
                Some(&["elicitation".to_string()]),
                &subc_protocol::RouteTarget::ToolProvider {
                    module_id: "cerebellum".into(),
                },
            ),
        );
        let mut arguments = json!({"target":"com.example.PermissionProbeNotInstalled"});
        match action {
            "type" => arguments["text"] = json!("hello"),
            "keys" => arguments["keys"] = json!(["s"]),
            "press_element" => arguments = json!({"element_id":"e1"}),
            "press_point" => arguments = json!({"image_id":"i1", "x":1, "y":1}),
            "write_text" => {
                arguments = json!({"element_id":"e1", "text":"hello", "write_mode":"replace_value"})
            }
            "takeover_move" => arguments = json!({"image_id":"i1", "to":{"x":1,"y":1}}),
            "takeover_drag" => {
                arguments = json!({"image_id":"i1", "from":{"x":1,"y":1}, "to":{"x":2,"y":2}})
            }
            "takeover_scroll" => {
                arguments["axis"] = json!("vertical");
                arguments["amount_lines"] = json!(1);
            }
            _ => {}
        }
        if name == "computer_use" {
            arguments["action"] = json!(action);
        }
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let journal_before = planes
            .computer
            .as_ref()
            .unwrap()
            .journal_entry_count()
            .await;
        crate::handle_frame(
            Frame::build(
                FrameType::Request,
                subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, true),
                7,
                1,
                42,
                serde_json::to_vec(&json!({"name":name, "arguments":arguments})).unwrap(),
            )
            .unwrap(),
            &tx,
            &planes,
        )
        .await
        .unwrap();
        let frame = tokio::time::timeout(HANG_GUARD, rx.recv())
            .await
            .expect("permission admission must answer without waiting for consent")
            .unwrap();
        assert_eq!(
            frame.header.ty,
            FrameType::Response,
            "a refusal must not ask consent: {}",
            String::from_utf8_lossy(&frame.body)
        );
        let reply = serde_json::from_slice(&frame.body).unwrap();
        assert_eq!(
            planes
                .computer
                .as_ref()
                .unwrap()
                .journal_entry_count()
                .await,
            journal_before
        );
        (reply, lookups.load(Ordering::SeqCst))
    }

    async fn assert_refuses(
        action: &str,
        report: PermissionLivenessReport,
        permission: &str,
        state: PermissionLiveness,
    ) {
        for name in ["computer_use".to_string(), format!("computer.{action}")] {
            let (reply, lookups) = call(&name, action, report.clone()).await;
            assert_eq!(reply["outcome"], "permission_missing", "{name}: {reply}");
            assert_eq!(
                reply["detail"],
                json!({"permission":permission,"state":state}),
                "{reply}"
            );
            assert_eq!(
                lookups, 0,
                "permission must be checked before target lookup"
            );
            let remedy = reply["remedy"].as_str().unwrap();
            assert!(remedy.contains("restart cerebellum"), "{reply}");
            if state == PermissionLiveness::GrantedPendingRelaunch {
                assert!(!remedy.contains("System Settings"), "{reply}");
            } else {
                assert!(remedy.starts_with("On macOS, grant "), "{reply}");
                assert!(
                    remedy.contains("System Settings") && remedy.contains("ck-cerebellum"),
                    "{reply}"
                );
            }
            if action == "type" || action == "keys" {
                assert_eq!(reply["effect_status"], "not_dispatched", "{reply}");
            }
        }
    }

    #[tokio::test]
    async fn permission_missing_type_is_refused_before_lookup_or_consent() {
        assert_refuses(
            "type",
            readings(PermissionLiveness::Unavailable),
            "accessibility",
            PermissionLiveness::Unavailable,
        )
        .await;
        let (reply, lookups) = call("computer_use", "type", live_for_test()).await;
        assert_eq!(
            reply["outcome"], "not_running",
            "the live control must reach lookup: {reply}"
        );
        // The check for an application no agent may use resolves the
        // target once before the action's own lookup does.
        assert_eq!(lookups, 2);
    }

    #[tokio::test]
    async fn permission_pending_relaunch_is_not_live() {
        assert_refuses(
            "type",
            readings(PermissionLiveness::GrantedPendingRelaunch),
            "accessibility",
            PermissionLiveness::GrantedPendingRelaunch,
        )
        .await;
    }

    #[tokio::test]
    async fn permission_requirements_refuse_each_advertised_row_over_the_wire() {
        for action in [
            "read_state",
            "press_element",
            "press_point",
            "write_text",
            "keys",
            "takeover_move",
            "takeover_drag",
            "takeover_scroll",
        ] {
            let capability = format!("computer.{action}");
            let mut services =
                cerebellum_computer::platform::vocabulary::required_permission_services(
                    &capability,
                )
                .unwrap();
            if matches!(action, "takeover_move" | "takeover_drag") {
                services.push(PermissionService::Accessibility);
            }
            for missing in services {
                for state in [
                    PermissionLiveness::Unavailable,
                    PermissionLiveness::Unresolved,
                    PermissionLiveness::ProbeFailed,
                    PermissionLiveness::GrantedPendingRelaunch,
                ] {
                    let report = PermissionLivenessReport::from_results(
                        [
                            PermissionService::Accessibility,
                            PermissionService::ScreenRecording,
                            PermissionService::InputMonitoring,
                            PermissionService::PostEvent,
                        ]
                        .into_iter()
                        .map(|service| PermissionProbeResult {
                            service,
                            liveness: if service == missing {
                                state
                            } else {
                                PermissionLiveness::Live
                            },
                            responsible_process: "ck-cerebellum".into(),
                            off_main: true,
                        }),
                    );
                    let permission = if missing == PermissionService::InputMonitoring {
                        "input_monitoring"
                    } else {
                        "accessibility"
                    };
                    assert_refuses(action, report, permission, state).await;
                }
            }
        }
        // For computer.type, deny PostEvent and InputMonitoring independently
        // while Accessibility stays live. Neither permission can be assumed
        // from the Accessibility grant.
        for missing in [
            PermissionService::PostEvent,
            PermissionService::InputMonitoring,
        ] {
            let report = PermissionLivenessReport::from_results(
                [
                    PermissionService::Accessibility,
                    PermissionService::PostEvent,
                    PermissionService::InputMonitoring,
                ]
                .into_iter()
                .map(|service| PermissionProbeResult {
                    service,
                    liveness: if service == missing {
                        PermissionLiveness::Unavailable
                    } else {
                        PermissionLiveness::Live
                    },
                    responsible_process: "ck-cerebellum".into(),
                    off_main: true,
                }),
            );
            assert_refuses(
                "type",
                report,
                if missing == PermissionService::PostEvent {
                    "accessibility"
                } else {
                    "input_monitoring"
                },
                PermissionLiveness::Unavailable,
            )
            .await;
        }
    }
}

/// A new platform row must not disappear in the module's second, explicit
/// release gate table. Test on every host without borrowing its TCC readings.
#[test]
fn every_advertised_platform_row_is_admitted_by_the_module_release_gate() {
    let context = context(PermissionLiveness::Live);
    let outcomes = crate::computer_gate_outcomes(&context);
    let advertised: Vec<_> = capability_declarations(&context, true)
        .into_iter()
        .filter(|row| row.advertised)
        .collect();
    assert_eq!(
        advertised.len(),
        12,
        "the all-bound fixture must exercise every vocabulary row"
    );
    let missing: Vec<_> = advertised
        .iter()
        .filter(|row| !crate::declaration_gate_passes(row, &outcomes))
        .map(|row| row.capability_id.as_str())
        .collect();
    assert!(
        missing.is_empty(),
        "platform-advertised capabilities missing a module release-gate arm: {missing:?}"
    );
}
