use super::*;
use crate::agent_grants::{AgentGrants, BrowserTarget, GrantHolder, GrantSubject};
use crate::browser_standing_grants::ManualWallClock;

fn rows(fixture: &Fixture) -> Vec<crate::agent_grants::AgentGrant> {
    let store = fixture.planes.management.agent_grants();
    store.live_rows(None, store.now_ms()).unwrap()
}

fn ask(tier: u8, hazards: Value, origin: &str) -> Value {
    json!({"browser":"user","action":"open_grant","origins":[origin],"hazards":hazards,"severity_tier":tier})
}

#[tokio::test]
async fn default_isolated_planes_record_user_browser_answers_in_unified_store() {
    let fixture = Fixture::with_stores(None, None, false);
    bind_probe_head(&fixture).await;
    let (reply, cards) = fixture
        .call(
            PROBE_CHANNEL,
            ask(1, json!([]), "http://127.0.0.1:53967"),
            "allow_30m",
        )
        .await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(cards.len(), 1);
    let rows = rows(&fixture);
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(
        row.holder,
        GrantHolder::Head {
            agent_id: PROBE_AGENT.into()
        }
    );
    assert_eq!(
        row.subject,
        GrantSubject::Origin("http://127.0.0.1:53967".into())
    );
    assert_eq!(row.browser_target, Some(BrowserTarget::UserBrowser));
    assert_eq!(row.machine_uuid, "isolated-plane");
    assert_eq!(row.expires_at_ms, Some(row.granted_at_ms + 1_800_000));
    assert_eq!(row.card_ref.as_deref(), Some("el_site_1"));
    assert_eq!(row.max_level, 2);
    assert!(row.hazards.is_empty());
}

const PROBE_CHANNEL: u16 = 9;
const PROBE_AGENT: &str = "pj-user-browser-probe";

// Use channel-zero admission with the probe's primary head facts and authorized
// Prefrontal stamp, rather than installing already-accepted facts in the route.
async fn bind_probe_head(fixture: &Fixture) {
    use subc_protocol::scope::{ScopeAttributes, ScopeKind, ScopeStamp};
    use subc_protocol::session::ModuleControlRequest;
    use subc_protocol::{BindIdentity, RouteTarget};

    let stamp = ScopeStamp::new(
        crate::session_caller_principal_for_test().unwrap(),
        "browser-tests",
        1,
        ScopeKind::Head,
    )
    .with_attributes(
        ScopeAttributes::new()
            .with_agent_id(Some(PROBE_AGENT.into()))
            .with_delegates(true),
    )
    .with_owner_authorized(true);
    let request = ModuleControlRequest::RouteBind {
        role_versions: None,
        call_mode: None,
        route_channel: PROBE_CHANNEL,
        epoch: 1,
        target: RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
        identity: BindIdentity::new("probe", "user-browser-probe"),
        principal: crate::session_caller_principal_for_test(),
        consumer_capabilities: None,
        admission_facts: Some(json!({"agentProjectId":PROBE_AGENT,"sessionKind":"primary",
            "effectiveCapabilityScope":["*"],"browserControlOperations":["browser.launch","browser.status","browser.close"]})),
        scope: Some(stamp),
    };
    let frame = Frame::build(
        subc_protocol::FrameType::Request,
        subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
        0,
        0,
        1,
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();
    let (writer, mut replies) = mpsc::channel(2);
    crate::handle_control_request_for_test_with_bindings(
        frame,
        &writer,
        &fixture.planes.health,
        &fixture.planes.routes,
    )
    .await
    .unwrap();
    assert_eq!(
        replies.recv().await.unwrap().header.ty,
        subc_protocol::FrameType::Response
    );
    let facts = fixture.planes.routes.get(PROBE_CHANNEL, 1).unwrap();
    assert_eq!(
        crate::permission_scope::minting_holder(&facts),
        Some(crate::agent_grants::GrantHolder::Head {
            agent_id: PROBE_AGENT.into()
        })
    );
}

#[tokio::test]
async fn prefrontal_head_offers_thirty_minutes_on_loopback_and_public_origins() {
    use crate::agent_grants::{FilesystemAgentGrantStorage, LegacyGrantStores};
    let mut fixture = Fixture::new();
    // Keep the installation's filesystem-backed unified grant path, but place
    // every file under the fixture instead of the operator's data home.
    let path = fixture.registry.join("agent-grants.json");
    let open = || {
        AgentGrants::open(
            Arc::new(FilesystemAgentGrantStorage::new(&path)),
            &LegacyGrantStores::beside(&path),
            Some("test-machine".into()),
        )
    };
    let store = Arc::new(open());
    assert!(store.can_record());
    Arc::get_mut(&mut fixture.planes).unwrap().management = Arc::new(
        crate::management::ManagementPlane::new(Arc::new(
            crate::management::PlatformResolver::new(),
        ))
        .with_agent_grants(store),
    );
    bind_probe_head(&fixture).await;
    for origin in ["http://127.0.0.1:53967", "https://example.com"] {
        let (reply, cards) = fixture
            .call(PROBE_CHANNEL, ask(1, json!([]), origin), "allow_30m")
            .await;
        assert_eq!(reply["outcome"], "ok", "{reply}");
        assert_eq!(cards.len(), 1);
        let ids: Vec<_> = cards[0]["options"]
            .as_array()
            .unwrap()
            .iter()
            .map(|option| option["id"].as_str().unwrap())
            .collect();
        assert_eq!(
            ids,
            ["allow_30m", "allow_origin_always", "deny"],
            "{origin}"
        );
    }
    assert_eq!(rows(&fixture).len(), 2);
    assert_eq!(open().live_rows(None, 0).unwrap().len(), 2);
}

#[tokio::test]
async fn probe_missing_store_refuses_before_raising_a_deny_only_card() {
    let mut fixture = Fixture::with_stores(None, None, false);
    Arc::get_mut(&mut fixture.planes).unwrap().management =
        Arc::new(crate::management::ManagementPlane::new(Arc::new(
            crate::management::PlatformResolver::new(),
        )));
    bind_probe_head(&fixture).await;
    assert!(fixture.planes.management.unified_agent_grants().is_none());
    assert!(!fixture.planes.user_browser.target().grants.can_record());
    let (reply, cards) = fixture
        .call(
            PROBE_CHANNEL,
            ask(1, json!([]), "http://127.0.0.1:53967"),
            "deny",
        )
        .await;
    assert_eq!(reply["reason"], "grant_store_unavailable", "{reply}");
    assert!(cards.is_empty());
}

#[tokio::test]
async fn user_site_card_requires_a_holder_and_a_recordable_unified_store() {
    for no_holder in [true, false] {
        let fixture = Fixture::with_agent_grants(
            None,
            Some(Arc::new(AgentGrants::in_memory(if no_holder {
                Some("test-machine".into())
            } else {
                None
            }))),
        );
        bind_probe_head(&fixture).await;
        if no_holder {
            let mut facts = fixture.planes.routes.get(PROBE_CHANNEL, 1).unwrap();
            facts.session_kind_attested = false;
            fixture.planes.routes.insert(PROBE_CHANNEL, 1, facts);
        }
        let (reply, cards) = fixture
            .call(
                PROBE_CHANNEL,
                ask(1, json!([]), "https://example.com"),
                "deny",
            )
            .await;
        assert_eq!(
            reply["reason"],
            if no_holder {
                "no_grant_holder"
            } else {
                "grant_store_unavailable"
            },
            "{reply}"
        );
        assert!(cards.is_empty());
        assert!(rows(&fixture).is_empty());
    }
}

#[tokio::test]
async fn user_site_upgrade_keeps_id_and_temporary_answer_expires_on_the_wall_clock() {
    // A non-default port keeps Always origin-scoped too: this tests a lifetime
    // replacement of the same subject, which must keep its revocable row id.
    let clock = Arc::new(ManualWallClock::at(1000));
    let store =
        Arc::new(AgentGrants::in_memory(Some("test-machine".into())).with_clock(clock.clone()));
    let fixture = Fixture::with_agent_grants(None, Some(store));
    let (reply, cards) = fixture
        .call(
            1,
            ask(1, json!([]), "https://example.com:8443"),
            "allow_30m",
        )
        .await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(cards.len(), 1);
    let first = rows(&fixture).remove(0);
    assert_eq!(first.expires_at_ms, Some(1_801_000));
    let (reply, cards) = fixture
        .call(
            1,
            ask(3, json!([]), "https://example.com:8443"),
            "allow_origin_always",
        )
        .await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(cards.len(), 1);
    let upgraded = rows(&fixture);
    assert_eq!(upgraded.len(), 1);
    assert_eq!(upgraded[0].id, first.id);
    assert_eq!(upgraded[0].browser_target, Some(BrowserTarget::UserBrowser));
    assert_eq!(upgraded[0].expires_at_ms, None);
    assert_eq!(upgraded[0].max_level, 3);
    // Shorten the upgraded site's lifetime in place; permanent authority must
    // not remain usable after the replacement's expiry.
    let mut replacement = upgraded[0].clone();
    replacement.expires_at_ms = Some(1_801_000);
    fixture
        .planes
        .management
        .agent_grants()
        .upsert(replacement, 1000)
        .unwrap();
    clock.advance_ms(1_800_000);
    let (reply, cards) = fixture
        .call(1, ask(1, json!([]), "https://example.com:8443"), "deny")
        .await;
    assert_eq!(reply["reason"], "consent_declined", "{reply}");
    assert_eq!(cards.len(), 1);
    assert!(rows(&fixture).is_empty());
}

/// A turn-stop ends a held site card's ability to grant, even when Cingulate
/// cannot confirm the withdrawal or reports that the person had already
/// answered: the answer that reaches a later drain is acknowledged, and no
/// grant row is created from it.
#[tokio::test]
async fn a_cancelled_site_card_never_grants_whatever_the_withdrawal_says() {
    for withdrawal in [
        Reply::Transport,
        Reply::Result(json!({"elicitation_id":"el_site_stop","state":"answered",
            "answered_choice_id":"allow_30m"})),
    ] {
        let script = ScriptedCingulate::new().accept_execution_reports();
        let fixture = Fixture::scripted(&script);
        let tab = fixture.claim(1).await;
        script
            .then(
                wire::CONSENT_REQUEST,
                Reply::Result(json!({"elicitation_id":"el_site_stop"})),
            )
            .then(wire::CONSENT_AWAIT, Reply::Hang)
            .then(wire::CONSENT_WITHDRAW, withdrawal);
        let started = fixture.start(1, snapshot_args(&tab), "");
        until(|| script.methods().len() == 2).await;
        fixture
            .planes
            .cancellations
            .get((1, 1, started.corr))
            .unwrap()
            .cancel();
        let reply = fixture.finish(started).await;
        assert_eq!(
            reply,
            json!({"browser":"user", "outcome":"cancelled", "input_dispatched":false})
        );
        let card = fixture.planes.consent.raised("el_site_stop").unwrap();
        assert!(!card.lifecycle.deferred_use);
        assert_eq!(card.lifecycle.user_browser_grant, None);
        assert_eq!(
            fixture
                .planes
                .consent
                .open_card_for(&this_session(), &card.subject),
            None,
            "a later call must not join the cancelled card"
        );

        let answered = json!({"elicitation_id":"el_site_stop","state":"answered",
            "answered_choice_id":"allow_30m"});
        script
            .then(wire::CONSENT_GET, Reply::Result(answered.clone()))
            .then(
                wire::CONSENT_ANSWERS,
                Reply::Result(json!({"records":[answered],"cursor":1})),
            )
            .then(wire::CONSENT_ACK, Reply::Result(json!({"cursor":1})));
        let status = fixture
            .finish(fixture.start_arbitrated(json!({"browser":"user","action":"status"})))
            .await;
        assert_eq!(status["outcome"], "ok", "{status}");
        assert!(
            script.methods().iter().any(|m| m == wire::CONSENT_ACK),
            "the issued answer is acknowledged"
        );
        assert!(rows(&fixture).is_empty(), "a cancelled card granted access");
    }
}

async fn late_site_answer(choice: &str, tier: u8) -> Fixture {
    late_site_answer_with_hazards(choice, tier, json!([]))
        .await
        .0
}

async fn late_site_answer_with_hazards(
    choice: &str,
    tier: u8,
    hazards: Value,
) -> (Fixture, Arc<ScriptedCingulate>) {
    let script = ScriptedCingulate::new().accept_execution_reports();
    let fixture = Fixture::scripted(&script);
    fixture.state.lock().unwrap().top_level_only = true;
    let args = if tier == 1 {
        let tab = fixture.claim(1).await;
        snapshot_args(&tab)
    } else {
        ask(tier, hazards, "https://example.com")
    };
    script
        .then(
            wire::CONSENT_REQUEST,
            Reply::Result(json!({"elicitation_id":"el_late_site"})),
        )
        .then(
            wire::CONSENT_AWAIT,
            Reply::Result(json!({"elicitation_id":"el_late_site","state":"pending"})),
        )
        .then(
            wire::CONSENT_DETACH,
            Reply::Result(
                json!({"elicitation_id":"el_late_site","state":"pending","detached":true}),
            ),
        );
    let reply = fixture.finish(fixture.start_arbitrated(args)).await;
    assert_eq!(reply["outcome"], "consent_pending", "{reply}");
    assert!(rows(&fixture).is_empty());
    // The observer may be replaced while consent is detached. The retry's new
    // read, not a pre-card observation, must authorize the following input.
    fixture.state.lock().unwrap().observer_continuity += 1;
    script
        .then(wire::CONSENT_ANSWERS, Reply::Result(json!({"records":[{"elicitation_id":"el_late_site","state":"answered","answered_choice_id":choice}],"cursor":1})))
        .then(wire::CONSENT_ACK, Reply::Result(json!({"cursor":1})));
    // Status does not retry the original demand. Its admitted-call drain must
    // nevertheless make the durable answer available to subsequent actions.
    let status = fixture
        .finish(fixture.start_arbitrated(json!({"browser":"user","action":"status"})))
        .await;
    assert_eq!(status["outcome"], "ok", "{status}");
    assert_eq!(
        script
            .methods()
            .iter()
            .filter(|m| m.as_str() == wire::CONSENT_REQUEST)
            .count(),
        1
    );
    (fixture, script)
}

async fn consent_scope_question(replies: &mut mpsc::Receiver<Frame>) -> Frame {
    let question = tokio::time::timeout(HANG_GUARD, replies.recv())
        .await
        .expect("scope describe is bounded")
        .expect("scope describe request");
    assert_eq!(question.header.ty, subc_protocol::FrameType::Request);
    assert_eq!(question.header.channel, 0);
    let body: Value = serde_json::from_slice(&question.body).unwrap();
    assert_eq!(body["op"], "scope.describe");
    assert_eq!(body["ref"], "card-tests");
    assert_eq!(body["owner"]["module_id"], "prefrontal");
    question
}

async fn answer_consent_scope(
    planes: &Planes,
    writer: &mpsc::Sender<Frame>,
    question: &Frame,
    ty: subc_protocol::FrameType,
    answer: Value,
) {
    let frame = Frame::build(
        ty,
        crate::control_flags(),
        0,
        0,
        question.header.corr,
        serde_json::to_vec(&answer).unwrap(),
    )
    .unwrap();
    crate::handle_frame_for_test(frame, writer, planes)
        .await
        .unwrap();
}

async fn wait_for_consent_session_end(planes: &Planes) {
    tokio::time::timeout(HANG_GUARD, async {
        while !planes
            .consent
            .raised("el_late_site")
            .unwrap()
            .lifecycle
            .ended
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("confirmed session end is recorded");
}

#[tokio::test]
async fn route_goodbye_waits_for_confirmed_session_end_without_revoking_the_saved_site_grant() {
    use crate::cingulate_client::wire::{Execution, ExecutionReason};
    let (fixture, script) = late_site_answer_with_hazards(
        "allow_origin_always",
        3,
        json!(["unverified_form_contents"]),
    )
    .await;
    let granted = rows(&fixture);
    let mut planes = (*fixture.planes).clone();
    planes.scopes = Arc::new(crate::scope_watch::ScopeRevocation::with_intervals(
        Duration::from_millis(10),
        HANG_GUARD,
    ));
    let (writer, mut replies) = mpsc::channel(8);
    for channel in [1, 2] {
        let goodbye = Frame::build(
            subc_protocol::FrameType::Goodbye,
            crate::control_flags(),
            channel,
            1,
            0,
            vec![],
        )
        .unwrap();
        crate::handle_frame_for_test(goodbye, &writer, &planes)
            .await
            .unwrap();
        assert!(planes.routes.get(channel, 1).is_none());
    }
    let question = consent_scope_question(&mut replies).await;
    assert_eq!(
        planes
            .consent
            .raised("el_late_site")
            .unwrap()
            .lifecycle
            .final_report,
        None
    );
    answer_consent_scope(
        &planes,
        &writer,
        &question,
        subc_protocol::FrameType::Error,
        json!({"code":"unavailable","message":"try again"}),
    )
    .await;
    let question = consent_scope_question(&mut replies).await;
    assert_eq!(
        planes
            .consent
            .raised("el_late_site")
            .unwrap()
            .lifecycle
            .final_report,
        None
    );
    assert_eq!(rows(&fixture), granted);
    answer_consent_scope(
        &planes,
        &writer,
        &question,
        subc_protocol::FrameType::Response,
        json!({"op":"scope.describe","status":"ended","scope_epoch":1,
            "daemon_incarnation":"test","owner_synced":true,"owner_configured":true}),
    )
    .await;
    wait_for_consent_session_end(&planes).await;
    let card = planes.consent.raised("el_late_site").unwrap();
    let report = card.lifecycle.final_report.unwrap();
    assert_eq!(report.execution, Execution::ApprovedNotExecuted);
    assert_eq!(report.reason, Some(ExecutionReason::SessionEnded));
    assert!(!card.lifecycle.dispatch_started);
    assert_eq!(rows(&fixture), granted);

    let frame = tool_frame(3, 1, json!({"browser":"user","action":"status"}));
    crate::install_test_bind(&planes.routes, &frame);
    let mut stamp = crate::computer_grants::tests::stamp("next-agent");
    stamp.scope_ref = "next-session".into();
    let facts = planes.routes.get(3, 1).unwrap().with_scope(Some(stamp));
    planes.routes.insert(3, 1, facts);
    script.report_features(Some(crate::cingulate_client::features::CingulateFeatures {
        option_group: true,
        single_use: false,
        no_expiry: true,
        secret_use_approval: true,
    }));
    fixture
        .call(3, json!({"browser":"user","action":"status"}), "")
        .await;
    let reports: Vec<_> = script
        .calls()
        .into_iter()
        .filter(|(method, _)| method == wire::CONSENT_REPORT_EXECUTION)
        .collect();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].1["execution"], "approved_not_executed");
    assert_eq!(reports[0].1["reason"], "session_ended");
    assert_eq!(rows(&fixture), granted);
}

#[tokio::test]
async fn restarted_consent_desk_waits_for_scope_evidence_before_settling_an_unused_grant() {
    use crate::cingulate_client::desk::ConsentDesk;
    use crate::cingulate_client::wire::{Execution, ExecutionReason};
    let (fixture, script) = late_site_answer_with_hazards(
        "allow_origin_always",
        3,
        json!(["unverified_form_contents"]),
    )
    .await;
    let granted = rows(&fixture);
    let mut recovered = (*fixture.planes).clone();
    recovered.consent = Arc::new(ConsentDesk::with_store(
        Arc::new(script.clone()),
        Arc::new(FileRegistryStore::new(
            fixture.registry.join("registry.json"),
        )),
    ));
    recovered.routes = Arc::new(crate::RouteBindings::default());
    recovered.scopes = Arc::new(crate::scope_watch::ScopeRevocation::with_intervals(
        Duration::from_millis(10),
        HANG_GUARD,
    ));
    let (writer, mut replies) = mpsc::channel(8);
    recovered.scopes.control.connect(&writer);
    crate::watch_retained_consent_scopes(&recovered, &writer);
    // Starting recovery twice must share the same watcher, not two describes.
    crate::watch_retained_consent_scopes(&recovered, &writer);
    for (ty, answer) in [
        (
            subc_protocol::FrameType::Response,
            json!({"op":"scope.describe","status":"not_live",
            "daemon_incarnation":"restarted","owner_synced":false,"owner_configured":true}),
        ),
        (
            subc_protocol::FrameType::Error,
            json!({"code":"unavailable","message":"try again"}),
        ),
        (
            subc_protocol::FrameType::Response,
            json!({"op":"scope.describe","status":"live","scope_epoch":1,
            "daemon_incarnation":"restarted","owner_synced":true,"owner_configured":true}),
        ),
    ] {
        let question = consent_scope_question(&mut replies).await;
        assert_eq!(recovered.scopes.control.outstanding(), 1);
        assert_eq!(
            recovered
                .consent
                .raised("el_late_site")
                .unwrap()
                .lifecycle
                .final_report,
            None
        );
        assert_eq!(rows(&fixture), granted);
        answer_consent_scope(&recovered, &writer, &question, ty, answer).await;
    }
    let question = consent_scope_question(&mut replies).await;
    assert_eq!(
        recovered
            .consent
            .raised("el_late_site")
            .unwrap()
            .lifecycle
            .final_report,
        None
    );
    answer_consent_scope(
        &recovered,
        &writer,
        &question,
        subc_protocol::FrameType::Response,
        json!({"op":"scope.describe","status":"ended","scope_epoch":1,
            "daemon_incarnation":"restarted","owner_synced":true,"owner_configured":true}),
    )
    .await;
    wait_for_consent_session_end(&recovered).await;
    let report = recovered
        .consent
        .raised("el_late_site")
        .unwrap()
        .lifecycle
        .final_report
        .unwrap();
    assert_eq!(report.execution, Execution::ApprovedNotExecuted);
    assert_eq!(report.reason, Some(ExecutionReason::SessionEnded));
    assert_eq!(rows(&fixture), granted);
}

#[tokio::test]
async fn retrying_open_grant_does_not_report_the_saved_permission_as_executed() {
    let (fixture, script) = late_site_answer_with_hazards(
        "allow_origin_always",
        3,
        json!(["unverified_form_contents"]),
    )
    .await;
    let reply = fixture
        .finish(fixture.start_arbitrated(ask(
            3,
            json!(["unverified_form_contents"]),
            "https://example.com",
        )))
        .await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(reply["input_dispatched"], false);
    let card = fixture.planes.consent.raised("el_late_site").unwrap();
    assert_eq!(card.lifecycle.final_report, None);
    assert!(!card.lifecycle.dispatch_started);
    assert_eq!(rows(&fixture).len(), 1);
    assert!(!script
        .methods()
        .iter()
        .any(|m| m == wire::CONSENT_REPORT_EXECUTION));
}

#[tokio::test]
async fn late_durable_site_approval_waits_for_retry_before_reporting_execution() {
    use crate::cingulate_client::wire::Execution;

    for choice in ["allow_30m", "allow_origin_always"] {
        let (fixture, script) =
            late_site_answer_with_hazards(choice, 3, json!(["unverified_form_contents"])).await;
        let granted = rows(&fixture);
        assert_eq!(granted.len(), 1);
        assert_eq!(granted[0].max_level, 3);
        assert_eq!(granted[0].card_ref.as_deref(), Some("el_late_site"));
        assert!(granted[0]
            .hazards
            .contains(&crate::authorization::HazardClass::UnverifiedFormContents));
        let card = fixture.planes.consent.raised("el_late_site").unwrap();
        assert!(card.applied && card.lifecycle.acked && card.lifecycle.deferred_use);
        assert!(!card.lifecycle.approval_taken && !card.lifecycle.dispatch_started);
        assert_eq!(card.lifecycle.final_report, None, "{choice}");
        assert!(!script
            .methods()
            .iter()
            .any(|m| m == wire::CONSENT_REPORT_EXECUTION));

        fixture.state.lock().unwrap().submit_button = true;
        let tab = fixture.claim(1).await;
        let (snapshot, _) = fixture.snapshot(1, &tab, "").await;
        assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
        script
            .then(
                wire::CONSENT_REQUEST,
                Reply::Result(json!({"elicitation_id":"el_stronger"})),
            )
            .then(
                wire::CONSENT_AWAIT,
                Reply::Result(json!({"elicitation_id":"el_stronger","state":"pending"})),
            )
            .then(
                wire::CONSENT_DETACH,
                Reply::Result(
                    json!({"elicitation_id":"el_stronger","state":"pending","detached":true}),
                ),
            );
        let reply = fixture
            .finish(fixture.start_arbitrated(click(&tab, &snapshot, &reference(&snapshot, "Go"))))
            .await;
        assert_eq!(reply["outcome"], "consent_pending", "{reply}");
        assert_eq!(reply["input_dispatched"], false);
        assert!(fixture.state.lock().unwrap().inputs.is_empty());
        let stronger = script
            .calls()
            .into_iter()
            .rfind(|(method, _)| method == wire::CONSENT_REQUEST)
            .unwrap()
            .1;
        assert_eq!(stronger["scope"]["severity_tier"], 4);
        let card = fixture.planes.consent.raised("el_late_site").unwrap();
        assert!(!card.lifecycle.dispatch_started);
        assert_eq!(
            card.lifecycle.final_report, None,
            "pending another permission is not a refusal of {choice}"
        );

        // A later ordinary click can use the saved grant without the stronger
        // permission. The earlier attempt classified its target but sent no input.
        fixture.state.lock().unwrap().submit_button = false;
        script
            .then(
                wire::CONSENT_ANSWERS,
                Reply::Result(json!({"records":[],"cursor":2})),
            )
            .then(wire::CONSENT_ACK, Reply::Result(json!({"cursor":2})));
        let (snapshot, _) = fixture.snapshot(1, &tab, "").await;
        script
            .then(
                wire::CONSENT_ANSWERS,
                Reply::Result(json!({"records":[],"cursor":2})),
            )
            .then(wire::CONSENT_ACK, Reply::Result(json!({"cursor":2})));
        let reply = fixture
            .finish(fixture.start_arbitrated(click(&tab, &snapshot, &reference(&snapshot, "Go"))))
            .await;
        assert_eq!(reply["outcome"], "ok", "{reply}");
        assert!(!fixture.state.lock().unwrap().inputs.is_empty());
        let card = fixture.planes.consent.raised("el_late_site").unwrap();
        assert!(card.lifecycle.dispatch_started);
        assert_eq!(
            card.lifecycle.final_report.unwrap().execution,
            Execution::Executed
        );

        script
            .then(
                wire::CONSENT_ANSWERS,
                Reply::Result(json!({"records":[],"cursor":2})),
            )
            .then(wire::CONSENT_ACK, Reply::Result(json!({"cursor":2})));
        fixture
            .call(1, json!({"browser":"user","action":"status"}), "")
            .await;
        let reports: Vec<_> = script
            .calls()
            .into_iter()
            .filter(|(method, _)| method == wire::CONSENT_REPORT_EXECUTION)
            .collect();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].1["execution"], "executed");
        assert!(reports[0].1.get("reason").is_none());
    }
}

#[tokio::test]
async fn late_read_site_answer_covers_click_without_another_card() {
    let fixture = late_site_answer("allow_30m", 1).await;
    let granted = rows(&fixture);
    assert_eq!(granted.len(), 1);
    assert_eq!(granted[0].max_level, 2);
    assert_eq!(granted[0].card_ref.as_deref(), Some("el_late_site"));
    assert_eq!(granted[0].browser_target, Some(BrowserTarget::UserBrowser));
    assert_eq!(
        granted[0].expires_at_ms,
        Some(granted[0].granted_at_ms + 1_800_000)
    );
    let tab = fixture.claim(1).await;
    let (snapshot, cards) = fixture.snapshot(1, &tab, "").await;
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    assert!(cards.is_empty());
    let (clicked, cards) = fixture.call(1, json!({"browser":"user","action":"click","tab":tab,"ref":reference(&snapshot, "Go"),"snapshot_id":snapshot["snapshot_id"],"intent":"click fixture","severity":{"tier":2,"credential":false,"financial":false}}), "").await;
    assert_eq!(clicked["outcome"], "ok", "{clicked}");
    assert!(cards.is_empty());
    assert!(fixture
        .planes
        .consent
        .take_single_use_approval(
            &this_session(),
            &fixture
                .planes
                .consent
                .raised("el_late_site")
                .unwrap()
                .subject
        )
        .is_none());
}

#[tokio::test]
async fn late_always_read_answer_grants_ordinary_site_use() {
    let fixture = late_site_answer("allow_origin_always", 1).await;
    let granted = rows(&fixture);
    assert_eq!(granted.len(), 1);
    assert_eq!(granted[0].expires_at_ms, None);
    assert_eq!(granted[0].max_level, 2);
    let holder = &granted[0].holder;
    assert!(fixture
        .planes
        .management
        .agent_grants()
        .authorize(
            holder,
            crate::agent_grants::GrantDemand::Browser {
                target: BrowserTarget::UserBrowser,
                origin: "https://example.com".into(),
                severity: Severity::new(2, false, false),
                hazards: BTreeSet::new(),
            }
        )
        .is_some());
    let tab = fixture.claim(1).await;
    let (snapshot, cards) = fixture.snapshot(1, &tab, "").await;
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    assert!(cards.is_empty());
}

#[tokio::test]
async fn in_call_read_site_answers_cover_clicks_and_typing() {
    for decision in ["allow_30m", "allow_origin_always"] {
        let fixture = Fixture::new();
        fixture.state.lock().unwrap().top_level_only = true;
        let tab = fixture.claim(1).await;
        let (snapshot, cards) = fixture.snapshot(1, &tab, decision).await;
        assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
        assert_eq!(cards.len(), 1);
        assert_eq!(rows(&fixture)[0].max_level, 2);
        assert_eq!(cards[0]["scope"]["severity_tier"], 2);
        assert_eq!(
            cards[0]["options"][0]["label"],
            "Allow on example.com for 30 minutes"
        );
        assert_eq!(cards[0]["options"][0]["detail"], "Covers reading, clicking and typing on this site; submitting forms and credential or financial actions still need approval.");
        let (clicked, cards) = fixture
            .call(
                1,
                click(&tab, &snapshot, &reference(&snapshot, "Go")),
                "deny",
            )
            .await;
        assert_eq!(clicked["outcome"], "ok", "{clicked}");
        assert!(cards.is_empty());
        let (typed, cards) = fixture.call(1, json!({"browser":"user","action":"type","tab":tab,"ref":reference(&snapshot, "Message"),"text":"ordinary site use","clear_first":true}), "deny").await;
        assert_eq!(typed["outcome"], "ok", "{typed}");
        assert!(cards.is_empty());
    }
}

#[tokio::test]
async fn ordinary_read_site_grant_still_asks_for_tier_three_actions_and_submits() {
    for form_submit in [false, true] {
        let fixture = Fixture::new();
        {
            let mut state = fixture.state.lock().unwrap();
            state.top_level_only = true;
            state.submit_button = form_submit;
        }
        let tab = fixture.claim(1).await;
        let (snapshot, cards) = fixture.snapshot(1, &tab, "allow_30m").await;
        assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
        assert_eq!(cards.len(), 1);
        let mut action = click(&tab, &snapshot, &reference(&snapshot, "Go"));
        action["severity"]["tier"] = json!(3);
        action["intent"] = json!(if form_submit {
            "submit fixture form"
        } else {
            "perform tier-three fixture action"
        });
        let (reply, cards) = fixture.call(1, action, "deny").await;
        assert_eq!(reply["reason"], "consent_declined", "{reply}");
        assert_eq!(cards.len(), 1);
        // A form owner's submit keeps its existing tier-four floor even when
        // the form has no credential or payment controls to disclose. An
        // ordinary target declared at tier three asks at exactly tier three.
        assert_eq!(
            cards[0]["scope"]["severity_tier"],
            if form_submit { 4 } else { 3 }
        );
        assert_eq!(cards[0]["scope"]["hazards"], json!([]));
        assert!(fixture.state.lock().unwrap().inputs.is_empty());
        let granted = rows(&fixture);
        assert_eq!(granted.len(), 1);
        assert_eq!(granted[0].max_level, 2);
        for hazard in [
            HazardClass::CredentialFormSubmit,
            HazardClass::FinancialFormSubmit,
        ] {
            assert!(fixture
                .planes
                .management
                .agent_grants()
                .authorize(
                    &granted[0].holder,
                    crate::agent_grants::GrantDemand::Browser {
                        target: BrowserTarget::UserBrowser,
                        origin: "https://example.com".into(),
                        severity: Severity::new(2, false, false),
                        hazards: [hazard].into_iter().collect(),
                    }
                )
                .is_none());
        }
    }
}

#[tokio::test]
async fn forged_user_browser_all_sites_answers_never_write_a_row() {
    for choice in ["allow_all_sites_30m", "allow_all_sites_always"] {
        let fixture = Fixture::new();
        let (reply, cards) = fixture
            .call(1, ask(3, json!([]), "https://example.com"), choice)
            .await;
        assert_eq!(reply["reason"], "unrecognized_answer", "{reply}");
        assert_eq!(cards.len(), 1);
        assert!(rows(&fixture).is_empty());
        for (origin, hazards) in [
            ("https://example.com", json!(["credential_form_submit"])),
            ("https://example.com", json!(["financial_form_submit"])),
            ("http://localhost", json!([])),
            ("http://10.0.0.5", json!([])),
            ("http://[::1]", json!([])),
        ] {
            let (reply, cards) = fixture.call(1, ask(3, hazards, origin), "deny").await;
            assert_eq!(reply["reason"], "consent_declined", "{origin}: {reply}");
            assert_eq!(cards.len(), 1, "{origin}");
            assert!(!cards[0]["options"]
                .as_array()
                .unwrap()
                .iter()
                .any(|option| option["group"] == "danger"));
        }
    }
}

#[test]
fn user_revoke_matches_only_the_callers_holder_target_and_subject() {
    use crate::agent_grants::{AgentGrant, GrantHolder, GrantSubject};
    let store = AgentGrants::in_memory(Some("test-machine".into()));
    let worker = |scope: &str| GrantHolder::Worker {
        agent_id: "head".into(),
        scope_ref: scope.into(),
    };
    let caller = worker("one");
    for (holder, target, domain) in [
        (caller.clone(), BrowserTarget::UserBrowser, "example.com"),
        (caller.clone(), BrowserTarget::AgentProfile, "example.com"),
        (caller.clone(), BrowserTarget::UserBrowser, "example.net"),
        (worker("two"), BrowserTarget::UserBrowser, "example.com"),
        (
            GrantHolder::Head {
                agent_id: "head".into(),
            },
            BrowserTarget::UserBrowser,
            "example.com",
        ),
    ] {
        // One clock reading: a millisecond tick between two reads would make a
        // worker grant one millisecond longer than its thirty-minute ceiling.
        let now = store.now_ms();
        store
            .upsert(
                AgentGrant {
                    id: String::new(),
                    holder,
                    subject: GrantSubject::Domain(domain.into()),
                    browser_target: Some(target),
                    machine_uuid: "test-machine".into(),
                    granted_at_ms: now,
                    expires_at_ms: Some(now + 1_800_000),
                    card_ref: Some("card".into()),
                    max_level: 3,
                    hazards: vec![],
                    team_id: None,
                    designated_requirement: None,
                },
                now,
            )
            .unwrap();
    }
    let reply = crate::user_browser::agent_enforcement::revoke_access(
        &store,
        Some(caller.clone()),
        &crate::browser_standing_grants::RevokeTarget::Domain("example.com".into()),
    );
    assert_eq!(reply["revoked"], 1);
    let remaining = store.live_rows(None, store.now_ms()).unwrap();
    assert_eq!(remaining.len(), 4);
    assert!(!remaining.iter().any(|row| row.holder == caller
        && row.browser_target == Some(BrowserTarget::UserBrowser)
        && row.subject == GrantSubject::Domain("example.com".into())));
}

#[tokio::test]
async fn user_browser_writer_rejects_broad_or_worker_permanent_answers() {
    use crate::management::BrowserGrantChoice;
    let fixture = Fixture::new();
    crate::permission_scope::test_support::describe(
        &fixture.planes,
        crate::permission_scope::test_support::live_head(),
    );
    for worker in [false, true] {
        let mut facts = fixture.planes.routes.get(1, 1).unwrap();
        if worker {
            let mut stamp = crate::cingulate_client::worker_vectors::worker_stamp();
            stamp.attributes.agent_id = Some("test-project".into());
            facts = facts.with_scope(Some(stamp));
        }
        let resolved = crate::permission_scope::resolve_worker(&facts, &fixture.planes.scopes)
            .await
            .unwrap();
        crate::permission_scope::WORKER_HOLDER
            .scope(resolved, async {
                let context = Context {
                    planes: &fixture.planes,
                    facts: &facts,
                    route: Route {
                        channel: 1,
                        epoch: 1,
                    },
                    inbound: Route {
                        channel: 1,
                        epoch: 1,
                    },
                    cancel: CancelHandle::pending(),
                    connection: fixture.epoch,
                    action: "open_grant",
                };
                for choice in [
                    BrowserGrantChoice::AllSitesThirtyMinutes,
                    BrowserGrantChoice::AllSitesAlways,
                    BrowserGrantChoice::OriginAlways,
                ] {
                    if !worker && choice == BrowserGrantChoice::OriginAlways {
                        continue;
                    }
                    let grant = InvocationGrant {
                        authorizing_row: None,
                        origin: "https://example.com".into(),
                        severity: Severity::new(3, false, false),
                        hazards: Default::default(),
                        once: false,
                    };
                    assert_eq!(
                        context
                            .record_agent_answer(grant, "card", choice)
                            .err()
                            .unwrap()["reason"],
                        "unrecognized_answer"
                    );
                }
            })
            .await;
    }
    assert!(rows(&fixture).is_empty());
}
