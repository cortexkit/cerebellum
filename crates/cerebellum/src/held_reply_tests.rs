//! Held first replies use the production dispatcher and the published wire vectors.

use super::*;
use crate::test_support::HANG_GUARD;
use cortexkit_role_tool_provider::{result, HELD_REPLY_V1, TOOL_RESULT_V1_CAPABILITY};
use std::sync::atomic::Ordering;

fn vectors() -> Value {
    serde_json::from_str(cortexkit_role_tool_provider::vectors::HELD_REPLY_V1_JSON).unwrap()
}

async fn exchange(planes: &Planes, channel: u16, corr: u64, body: Value) -> Frame {
    let (tx, mut rx) = mpsc::channel(16);
    handle_frame_for_test(request(channel, corr, body), &tx, planes)
        .await
        .unwrap();
    tokio::time::timeout(HANG_GUARD, rx.recv())
        .await
        .expect("the provider must answer; consent may not park for 120 seconds")
        .unwrap()
}

async fn bind_held(planes: &Planes) {
    bind_head(planes).await;
    let mut bind = run_bind(run_stamp());
    if let ModuleControlRequest::RouteBind {
        consumer_capabilities,
        ..
    } = &mut bind
    {
        *consumer_capabilities = Some(vec![TOOL_RESULT_V1_CAPABILITY.into(), HELD_REPLY_V1.into()]);
    }
    assert_eq!(
        exchange(planes, 0, 2, serde_json::to_value(bind).unwrap())
            .await
            .header
            .ty,
        FrameType::Response
    );
}

fn decode(frame: Frame) -> Value {
    assert_eq!(
        frame.header.ty,
        FrameType::Response,
        "{}",
        String::from_utf8_lossy(&frame.body)
    );
    serde_json::from_slice(&frame.body).unwrap()
}

fn assert_held(reply: &Value, reason: &str) {
    assert_eq!(reply["held"]["reason"], reason, "{reply}");
    assert_ne!(reply["isError"], true, "{reply}");
    assert!(reply.get("errorCode").is_none(), "{reply}");
    let decoded: result::ToolResult = serde_json::from_value(reply.clone()).unwrap();
    result::validate(&decoded).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), *reply);
}

fn grant_request(key: Option<&str>) -> Value {
    let mut request = json!({"name":"browser_use","arguments":{
        "action":"open_grant","origins":["https://example.com"],"hazards":[]}});
    if let Some(key) = key {
        request["call_key"] = json!(key);
    }
    request
}

async fn late(planes: &Planes, channel: u16) -> Value {
    decode(
        exchange(
            planes,
            channel,
            50,
            json!({"name":"late_results","arguments":{"since":null}}),
        )
        .await,
    )
}

fn answered(id: &str, choice: &str) -> Value {
    json!({"elicitation_id":id,"state":"answered","answered_choice_id":choice})
}

#[tokio::test]
async fn declared_consent_is_held_immediately_without_parking() {
    let consent = tests::ScriptedConsent::new();
    detach(&consent, "held-site");
    let planes = attach_consent(
        isolated_test_planes(&Arc::new(HealthState::new())),
        &consent,
    );
    bind_held(&planes).await;
    let reply = tokio::time::timeout(
        HANG_GUARD,
        exchange(&planes, 9, 3, grant_request(Some("held-site-key"))),
    )
    .await
    .expect("a held reply must not spend the 120-second consent park");
    let reply = decode(reply);
    assert_held(&reply, "consent");
    assert_eq!(reply["held"]["detail"]["ask_id"], "held-site");
    assert_eq!(reply["held"]["detail"]["origin"], "https://example.com");
    assert_eq!(reply["held"]["detail"]["kind"], "website_access_in_advance");
    assert!(planes.calls.has_pending_consents());
    assert!(!consent
        .methods()
        .iter()
        .any(|method| method == cingulate_client::wire::CONSENT_AWAIT));
    for scope in consent.script.scopes() {
        assert_eq!(scope.scope_ref, "head");
    }
}

#[tokio::test]
async fn undeclared_codemode_route_keeps_held_unsupported() {
    let consent = tests::ScriptedConsent::new();
    detach(&consent, "old-carrier");
    let planes = attach_consent(
        isolated_test_planes(&Arc::new(HealthState::new())),
        &consent,
    );
    bind_head(&planes).await;
    exchange(
        &planes,
        0,
        2,
        serde_json::to_value(run_bind(run_stamp())).unwrap(),
    )
    .await;
    let reply = decode(exchange(&planes, 9, 3, grant_request(Some("old-key"))).await);
    assert_eq!(reply["errorCode"], "held_unsupported", "{reply}");
    assert_eq!(reply["isError"], true);
    assert!(reply.get("held").is_none());
    assert!(!planes.calls.has_pending_consents());
}

#[tokio::test]
async fn declared_route_without_call_key_never_holds() {
    let consent = tests::ScriptedConsent::new();
    detach(&consent, "no-key");
    let planes = attach_consent(
        isolated_test_planes(&Arc::new(HealthState::new())),
        &consent,
    );
    bind_held(&planes).await;
    let reply = decode(exchange(&planes, 9, 3, grant_request(None)).await);
    assert!(reply.get("held").is_none(), "{reply}");
    assert_eq!(reply["errorCode"], "held_unsupported");
    assert!(!planes.calls.has_pending_consents());
}

async fn projected(
    mut facts: AcceptedBindFacts,
    caps: Vec<String>,
    mode: CallMode,
    tool: &str,
    keyed: bool,
    body: Value,
) -> Value {
    facts.consumer_capabilities = caps;
    facts.call_mode = mode;
    let (tx, mut rx) = mpsc::channel(1);
    let send = codemode::CALL_DETAIL.scope(
        std::cell::RefCell::new(Some(json!({"origin":"https://example.com"}))),
        tool_result::RESULT_BIND.scope(Some((tool.into(), facts)), async {
            send_tool_response(&tx, PROTOCOL_VERSION, 9, 3, 7, body)
                .await
                .unwrap();
        }),
    );
    if keyed {
        call_context::CALL_KEY
            .scope("projection-key".into(), send)
            .await;
    } else {
        send.await;
    }
    decode(rx.recv().await.unwrap())
}

#[tokio::test]
async fn held_gate_uses_bind_declarations_not_call_mode_and_requires_tool_opt_in() {
    let facts = bound_run().await.routes.get(9, 3).unwrap();
    for case in vectors()["gating"].as_array().unwrap() {
        let caps: Option<Vec<String>> =
            serde_json::from_value(case["consumer_capabilities"].clone()).unwrap();
        for mode in [CallMode::Classic, CallMode::Codemode] {
            let reply = projected(
                facts.clone(),
                caps.clone().unwrap_or_default(),
                mode,
                "browser_use",
                true,
                json!({"outcome":"consent_pending","ask_id":"gate"}),
            )
            .await;
            assert_eq!(
                reply.get("held").is_some(),
                case["held"].as_bool().unwrap(),
                "{}: {reply}",
                case["name"]
            );
        }
    }
    let reply = projected(
        facts,
        vec![TOOL_RESULT_V1_CAPABILITY.into(), HELD_REPLY_V1.into()],
        CallMode::Codemode,
        "tool.withdraw",
        true,
        json!({"outcome":"consent_pending","ask_id":"gate"}),
    )
    .await;
    assert!(reply.get("held").is_none());
}

#[tokio::test]
async fn production_held_replies_round_trip_published_vectors() {
    let facts = bound_run().await.routes.get(9, 3).unwrap();
    let vectors = vectors();
    for (outcome, vector_name) in [
        ("consent_pending", "held_consent"),
        ("login_pending", "held_login_handoff"),
        ("capture_pending", "held_login_capture"),
    ] {
        let expected = vectors["valid"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == vector_name)
            .unwrap();
        let expected: result::ToolResult =
            serde_json::from_value(expected["body"].clone()).unwrap();
        result::validate(&expected).unwrap();
        let reply = projected(facts.clone(), vec![TOOL_RESULT_V1_CAPABILITY.into(), HELD_REPLY_V1.into()], CallMode::Codemode, "browser_use", true,
            json!({"outcome":outcome,"ask_id":"opaque-ask","origin":"https://example.com","expires_in_ms":60000})).await;
        assert_held(&reply, &expected.held.unwrap().reason);
        assert_eq!(reply["held"]["detail"]["expires_in_ms"], 60000);
    }
    for case in vectors["valid"].as_array().unwrap() {
        let decoded: result::ToolResult = serde_json::from_value(case["body"].clone()).unwrap();
        result::validate(&decoded).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), case["body"]);
    }
    for case in vectors["invalid"].as_array().unwrap() {
        let decoded: result::ToolResult = serde_json::from_value(case["body"].clone()).unwrap();
        let problem = result::validate(&decoded).unwrap_err();
        assert_eq!(problem.member, case["member"]);
        assert_eq!(problem.reason, case["reason"]);
    }
    for case in vectors["decode_invalid"].as_array().unwrap() {
        assert!(serde_json::from_value::<result::ToolResult>(case["body"].clone()).is_err());
    }
}

#[tokio::test]
async fn declared_terminal_refusals_never_hold() {
    let facts = bound_run().await.routes.get(9, 3).unwrap();
    for outcome in [
        "consent_unavailable",
        "profile_busy",
        "resource_busy",
        "credential_form_submit",
        "financial_form_submit",
        "invalid_request",
        "call_mode_unsupported",
        "no_session",
        "capture_url_outside_domain",
    ] {
        let reply = projected(
            facts.clone(),
            vec![TOOL_RESULT_V1_CAPABILITY.into(), HELD_REPLY_V1.into()],
            CallMode::Codemode,
            "browser_use",
            true,
            json!({"outcome":outcome}),
        )
        .await;
        assert!(reply.get("held").is_none(), "{reply}");
        assert_eq!(reply["errorCode"], outcome);
    }
}

#[tokio::test]
async fn approved_consent_settles_basal_not_started_then_new_key_uses_grant() {
    let consent = tests::ScriptedConsent::new();
    detach(&consent, "approved-site");
    let planes = attach_consent(
        isolated_test_planes(&Arc::new(HealthState::new())),
        &consent,
    );
    bind_held(&planes).await;
    assert_held(
        &decode(exchange(&planes, 9, 3, grant_request(Some("site-approval"))).await),
        "consent",
    );
    consent.feed(json!([answered("approved-site", "allow_30m")]));
    let entries = late(&planes, 9).await;
    let entry = &entries["entries"][0];
    assert_eq!(entry["kind"], "not_started", "{entries}");
    assert_eq!(entry["custodian"], "reserved:basal");
    assert_eq!(entry["call_key"], "site-approval");
    assert_eq!(entry["detail"]["consent"], "approved");
    assert_eq!(
        entry["result"]["structuredContent"]["detail"]["consent"],
        "approved"
    );
    assert!(entry["result"]["content"]
        .to_string()
        .contains("Approved; call again to run it."));
    assert!(
        late(&planes, 8).await["entries"]
            .as_array()
            .unwrap()
            .is_empty(),
        "the head is not the custodian"
    );
    let retry = decode(exchange(&planes, 9, 4, grant_request(Some("site-retry"))).await);
    assert!(retry.get("held").is_none(), "{retry}");
    assert_ne!(retry["isError"], true, "{retry}");
    assert_eq!(consent.cards().len(), 1);
    assert!(!planes.calls.has_pending_consents());
}

#[tokio::test]
async fn denied_withdrawn_and_expired_consent_settle_terminally() {
    for (state, choice, expected) in [
        ("answered", Some("deny"), "denied"),
        ("withdrawn", None, "withdrawn"),
        ("expired", None, "expired"),
    ] {
        let consent = tests::ScriptedConsent::new();
        detach(&consent, "terminal-site");
        let planes = attach_consent(
            isolated_test_planes(&Arc::new(HealthState::new())),
            &consent,
        );
        bind_held(&planes).await;
        assert_held(
            &decode(exchange(&planes, 9, 3, grant_request(Some("terminal-key"))).await),
            "consent",
        );
        let mut record = json!({"elicitation_id":"terminal-site","state":state});
        if let Some(choice) = choice {
            record["answered_choice_id"] = json!(choice);
        }
        consent.feed(json!([record]));
        let entries = late(&planes, 9).await;
        let entry = &entries["entries"][0];
        assert_eq!(entry["detail"]["consent"], expected, "{entries}");
        assert_eq!(entry["result"]["isError"], true);
        assert_eq!(entry["result"]["errorCode"], expected);
        assert!(entry["result"].get("held").is_none());
        assert!(!planes.calls.has_pending_consents());
    }
}

fn capture_request(key: &str) -> Value {
    json!({"name":"browser_use","call_key":key,"arguments":{
        "action":"capture_login","credential_domain":"ollama.com","account":"work",
        "fetch_url":"https://ollama.com/settings","login_url":"https://ollama.com/signin"}})
}

#[tokio::test]
async fn consent_approval_never_executes_original_capture_and_retry_holds_login_capture() {
    let fixture = login_capture::test_support::fixture_with(|env| {
        env.poll_interval = Duration::from_millis(20);
        env.handoff_duration = Duration::from_secs(60);
    });
    let consent = tests::ScriptedConsent::new();
    detach(&consent, "capture-approval");
    let planes = attach_consent(tests::capture_planes(&fixture), &consent);
    bind_held(&planes).await;
    assert_held(
        &decode(exchange(&planes, 9, 3, capture_request("capture-original")).await),
        "consent",
    );
    assert_eq!(fixture.launcher.launches.load(Ordering::SeqCst), 0);
    consent.feed(json!([answered("capture-approval", "allow")]));
    let entries = late(&planes, 9).await;
    assert_eq!(
        entries["entries"][0]["detail"]["consent"], "approved",
        "{entries}"
    );
    assert_eq!(
        fixture.launcher.launches.load(Ordering::SeqCst),
        0,
        "approval cannot launch the original capture; only an explicit retry may do that"
    );
    assert_eq!(fixture.vault.calls(), 0);
    let reply = tokio::time::timeout(
        HANG_GUARD,
        exchange(&planes, 9, 4, capture_request("capture-retry")),
    )
    .await
    .unwrap();
    assert_held(&decode(reply), "login_capture");
    assert_eq!(consent.cards().len(), 1);
    assert_eq!(fixture.launcher.launches.load(Ordering::SeqCst), 1);
    let result = tokio::time::timeout(HANG_GUARD, async {
        loop {
            let entries = late(&planes, 9).await;
            if let Some(entry) = entries["entries"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["call_key"] == "capture-retry")
            {
                break entry.clone();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the capture completion owes basal a late result");
    assert_eq!(result["kind"], "result");
    assert_eq!(result["custodian"], "reserved:basal");
    assert_eq!(
        result["result"]["structuredContent"]["outcome"], "captured",
        "{result}"
    );
}

#[tokio::test]
async fn consent_custody_survives_restart_and_uses_existing_retention_and_ack() {
    use cortexkit_role_tool_provider::late_results::{AckRequest, LateResultsRequest};
    use journal::call_records::{CallRecords, InMemoryCallRecordStorage};
    let storage = InMemoryCallRecordStorage::new();
    let consent = tests::ScriptedConsent::new();
    detach(&consent, "restart-card");
    let mut planes = attach_consent(
        isolated_test_planes(&Arc::new(HealthState::new())),
        &consent,
    );
    planes.calls = Arc::new(CallRecords::open(
        Box::new(storage.clone()),
        wall_clock_ms(),
    ));
    bind_held(&planes).await;
    assert_held(
        &decode(exchange(&planes, 9, 3, grant_request(Some("restart-key"))).await),
        "consent",
    );
    let disk = String::from_utf8(storage.contents().unwrap()).unwrap();
    assert!(
        disk.starts_with("{\"format\":\"call-records\",\"version\":5}"),
        "{disk}"
    );
    drop(planes);
    let now = wall_clock_ms();
    let restarted = CallRecords::open(Box::new(storage.clone()), now);
    let reply = restarted
        .late_results("reserved:basal", &LateResultsRequest::new(), now)
        .unwrap();
    assert_eq!(reply.entries.len(), 1);
    let entry = &reply.entries[0];
    assert_eq!(entry.kind, "not_started");
    assert_eq!(entry.call_key, "restart-key");
    assert_eq!(entry.extra["detail"]["consent"], "withdrawn");
    let again = CallRecords::open(Box::new(storage.clone()), now + 1);
    let repeat = again
        .late_results("reserved:basal", &LateResultsRequest::new(), now + 1)
        .unwrap();
    assert_eq!(entry.event_id, repeat.entries[0].event_id);
    let expired = again
        .late_results(
            "reserved:basal",
            &LateResultsRequest::new(),
            now + 24 * 60 * 60 * 1000,
        )
        .unwrap();
    assert_eq!(expired.entries[0].kind, "expired");
    again
        .ack_late_results(
            "reserved:basal",
            &AckRequest {
                through: expired.cursor,
            },
            now + 24 * 60 * 60 * 1000,
        )
        .unwrap();
    let acked = CallRecords::open(Box::new(storage), now + 24 * 60 * 60 * 1000 + 1);
    assert!(acked
        .late_results(
            "reserved:basal",
            &LateResultsRequest::new(),
            now + 24 * 60 * 60 * 1000 + 1
        )
        .unwrap()
        .entries
        .is_empty());
}

struct LoginBrowser(Arc<std::sync::atomic::AtomicBool>);
impl browser_session::OwnedBrowserProcess for LoginBrowser {
    fn present(&mut self, _: &str, _: u64) -> Result<(), browser_session::NavigationDriveError> {
        Ok(())
    }
    fn cookie_names_for_origin(
        &mut self,
        _: &str,
        _: &str,
        _: u64,
    ) -> Result<std::collections::BTreeSet<String>, browser_session::NavigationDriveError> {
        Ok(if self.0.load(Ordering::SeqCst) {
            std::collections::BTreeSet::from(["session".into()])
        } else {
            std::collections::BTreeSet::new()
        })
    }
    fn has_credential_field(
        &mut self,
        _: &str,
        _: u64,
    ) -> Result<bool, browser_session::NavigationDriveError> {
        Ok(!self.0.load(Ordering::SeqCst))
    }
    fn main_frame_url(
        &mut self,
        _: &str,
        _: u64,
    ) -> Result<String, browser_session::NavigationDriveError> {
        Ok("https://example.com/signin".into())
    }
    fn generation_matches(&self) -> bool {
        true
    }
    fn request_graceful_termination(
        &mut self,
    ) -> Result<(), browser_session::ProcessControlFailure> {
        Ok(())
    }
    fn wait_for_exit(
        &mut self,
        _: Duration,
    ) -> Result<bool, browser_session::ProcessControlFailure> {
        Ok(true)
    }
    fn force_terminate(&mut self) -> Result<(), browser_session::ProcessControlFailure> {
        Ok(())
    }
    fn wait_until_reaped(&mut self) -> Result<(), browser_session::ProcessControlFailure> {
        Ok(())
    }
}
struct Cleanup;
impl browser_session::SessionCleanup for Cleanup {
    fn after_reap(
        &mut self,
    ) -> Result<browser_session::SessionCleanupOutcome, browser_session::CleanupStage> {
        Ok(browser_session::SessionCleanupOutcome::Complete)
    }
}

#[tokio::test]
async fn present_holds_login_handoff_and_settles_under_basal_call_key() {
    let mut planes = isolated_test_planes(&Arc::new(HealthState::new()));
    let config = Planes::short_test_browser_config();
    planes.browser_config = Some(config.clone());
    bind_held(&planes).await;
    assert!(matches!(
        planes.sessions.acquire_launch_slot("head-conversation"),
        browser_session::LaunchSlot::Acquired { .. }
    ));
    let logged_in = Arc::new(std::sync::atomic::AtomicBool::new(false));
    assert!(planes
        .sessions
        .establish_ready(
            "head-conversation",
            ProfileDisposition::Disposable,
            &config,
            planes.lease_clock.as_ref(),
            Box::new(LoginBrowser(logged_in.clone())),
            Box::new(Cleanup)
        )
        .is_some());
    let reply = tokio::time::timeout(HANG_GUARD, exchange(&planes, 9, 3, json!({"name":"browser_use","call_key":"present-held","arguments":{"action":"present","origin":"https://example.com"}}))).await.unwrap();
    assert_held(&decode(reply), "login_handoff");
    logged_in.store(true, Ordering::SeqCst);
    let entry = tokio::time::timeout(HANG_GUARD, async {
        loop {
            let entries = late(&planes, 9).await;
            if !entries["entries"].as_array().unwrap().is_empty() {
                break entries["entries"][0].clone();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the handoff poller owes basal the final answer");
    assert_eq!(entry["kind"], "result");
    assert_eq!(entry["custodian"], "reserved:basal");
    assert_eq!(entry["call_key"], "present-held");
    assert_eq!(
        entry["result"]["structuredContent"]["outcome"], "login_observed",
        "{entry}"
    );
}

#[tokio::test]
async fn replay_negotiates_held_again_for_the_current_route() {
    let consent = tests::ScriptedConsent::new();
    detach(&consent, "replay-card");
    let planes = attach_consent(
        isolated_test_planes(&Arc::new(HealthState::new())),
        &consent,
    );
    bind_held(&planes).await;
    assert_held(
        &decode(exchange(&planes, 9, 3, grant_request(Some("replay-key"))).await),
        "consent",
    );
    for declares_held in [false, true] {
        let mut facts = planes.routes.get(9, 3).unwrap();
        facts.consumer_capabilities = vec![TOOL_RESULT_V1_CAPABILITY.into()];
        if declares_held {
            facts.consumer_capabilities.push(HELD_REPLY_V1.into());
        }
        planes.routes.insert(9, 3, facts);
        consent.feed(json!([]));
        let reply = decode(exchange(&planes, 9, 4, grant_request(Some("replay-key"))).await);
        if declares_held {
            assert_held(&reply, "consent");
        } else {
            assert!(reply.get("held").is_none(), "{reply}");
            assert_eq!(reply["errorCode"], "held_unsupported");
        }
    }
    assert_eq!(consent.cards().len(), 1);
}

#[tokio::test]
async fn app_and_takeover_cards_hold_as_consent_without_parking() {
    use computer_grants::{ConsentRefusal, GrantNeed, SignedByFixtureTeam};
    use journal::call_records::Begin;
    for need in [
        GrantNeed::App {
            bundle_identity: "com.example.Test".into(),
            display_name: "Test".into(),
            code: Arc::new(SignedByFixtureTeam),
        },
        GrantNeed::Takeover,
    ] {
        let consent = tests::ScriptedConsent::new();
        detach(&consent, "computer-held");
        let planes = attach_consent(
            isolated_test_planes(&Arc::new(HealthState::new())),
            &consent,
        );
        bind_held(&planes).await;
        let facts = planes.routes.get(9, 3).unwrap();
        assert!(matches!(
            planes.calls.begin_scoped(
                "reserved:basal",
                "computer-key",
                "head-conversation",
                facts
                    .scope
                    .as_ref()
                    .map(journal::call_records::ScopeIdentity::from_stamp),
                wall_clock_ms()
            ),
            Begin::Execute(_)
        ));
        let (tx, mut rx) = mpsc::channel(1);
        let operation = async {
            let context = consent_context(&planes, &facts, &tx, 9, 3);
            let refusal = planes
                .management
                .computer_grants()
                .require(&need, &context, &CancelHandle::pending())
                .await
                .unwrap_err();
            assert!(matches!(refusal, ConsentRefusal::Pending { .. }));
            send_tool_response(&tx, PROTOCOL_VERSION, 9, 3, 3, refusal.reply(None))
                .await
                .unwrap();
        };
        call_context::ROUTE_GUARD
            .scope(
                Arc::new(planes.health.enter_request()),
                codemode::CALL_DETAIL.scope(
                    std::cell::RefCell::new(Some(json!({"action":"read_state"}))),
                    tool_result::RESULT_BIND.scope(
                        Some(("computer_use".into(), facts.clone())),
                        codemode::CALL_RECORDS.scope(
                            planes.calls.clone(),
                            call_context::CALL_KEY.scope("computer-key".into(), operation),
                        ),
                    ),
                ),
            )
            .await;
        let reply = decode(rx.recv().await.unwrap());
        assert_held(&reply, "consent");
        assert!(reply["held"]["detail"]["app"].is_string());
        assert!(planes.calls.has_pending_consents());
        assert!(!consent
            .methods()
            .iter()
            .any(|method| method == cingulate_client::wire::CONSENT_AWAIT));
    }
}

struct CustodyGate {
    block: std::sync::atomic::AtomicBool,
    entered: tokio::sync::Notify,
    released: std::sync::Mutex<bool>,
    wake: std::sync::Condvar,
}
impl CustodyGate {
    fn intercept(&self, version: u64) {
        if version == 5 && self.block.swap(false, Ordering::SeqCst) {
            self.entered.notify_one();
            let mut released = self.released.lock().unwrap();
            while !*released {
                released = self.wake.wait(released).unwrap();
            }
        }
    }
}
struct ReleaseCustody(Arc<CustodyGate>);
impl Drop for ReleaseCustody {
    fn drop(&mut self) {
        *self.0.released.lock().unwrap() = true;
        self.0.wake.notify_all();
    }
}
struct GatedStorage {
    inner: journal::call_records::InMemoryCallRecordStorage,
    gate: Arc<CustodyGate>,
}
impl journal::call_records::CallRecordStorage for GatedStorage {
    fn load(&self) -> Result<Option<Vec<u8>>, journal::call_records::CallRecordError> {
        self.inner.load()
    }
    fn append(
        &self,
        bytes: &[u8],
        version: u64,
    ) -> Result<(), journal::call_records::CallRecordError> {
        self.gate.intercept(version);
        self.inner.append(bytes, version)
    }
    fn replace(
        &self,
        bytes: &[u8],
        version: u64,
    ) -> Result<(), journal::call_records::CallRecordError> {
        self.gate.intercept(version);
        self.inner.replace(bytes, version)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn consent_drain_cannot_overtake_the_held_custody_write() {
    let gate = Arc::new(CustodyGate {
        block: std::sync::atomic::AtomicBool::new(true),
        entered: tokio::sync::Notify::new(),
        released: std::sync::Mutex::new(false),
        wake: std::sync::Condvar::new(),
    });
    let release = ReleaseCustody(gate.clone());
    let consent = tests::ScriptedConsent::new();
    detach(&consent, "racing-card");
    let mut planes = attach_consent(
        isolated_test_planes(&Arc::new(HealthState::new())),
        &consent,
    );
    planes.calls = Arc::new(journal::call_records::CallRecords::open(
        Box::new(GatedStorage {
            inner: journal::call_records::InMemoryCallRecordStorage::new(),
            gate: gate.clone(),
        }),
        wall_clock_ms(),
    ));
    bind_held(&planes).await;
    let planes = Arc::new(planes);
    let raising = {
        let planes = planes.clone();
        tokio::spawn(
            async move { exchange(&planes, 9, 3, grant_request(Some("racing-key"))).await },
        )
    };
    tokio::time::timeout(HANG_GUARD, gate.entered.notified())
        .await
        .expect("the real custody write was reached");
    consent.feed(json!([answered("racing-card", "allow_30m")]));
    let poll = late(&planes, 9);
    tokio::pin!(poll);
    tokio::select! {
        _ = &mut poll => panic!("an answer drain overtook the blocked custody write"),
        _ = tokio::time::sleep(Duration::from_millis(100)) => {}
    }
    assert!(
        !consent
            .methods()
            .iter()
            .any(|method| method == cingulate_client::wire::CONSENT_ANSWERS),
        "the feed must remain unread until the held obligation is durable"
    );
    drop(release);
    assert_held(&decode(raising.await.unwrap()), "consent");
    let result = tokio::time::timeout(HANG_GUARD, poll).await.unwrap();
    assert_eq!(result["entries"][0]["detail"]["consent"], "approved");
}

struct FailingStorage {
    inner: journal::call_records::InMemoryCallRecordStorage,
    fail: Arc<std::sync::atomic::AtomicBool>,
}
impl journal::call_records::CallRecordStorage for FailingStorage {
    fn load(&self) -> Result<Option<Vec<u8>>, journal::call_records::CallRecordError> {
        self.inner.load()
    }
    fn append(
        &self,
        bytes: &[u8],
        version: u64,
    ) -> Result<(), journal::call_records::CallRecordError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(journal::call_records::CallRecordError::WriteFailed(
                "injected custody failure".into(),
            ));
        }
        self.inner.append(bytes, version)
    }
    fn replace(
        &self,
        bytes: &[u8],
        version: u64,
    ) -> Result<(), journal::call_records::CallRecordError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(journal::call_records::CallRecordError::WriteFailed(
                "injected custody failure".into(),
            ));
        }
        self.inner.replace(bytes, version)
    }
}

#[tokio::test]
async fn failed_consent_custody_settlement_does_not_ack_the_answer() {
    let consent = tests::ScriptedConsent::new();
    detach(&consent, "failed-custody");
    let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut planes = attach_consent(
        isolated_test_planes(&Arc::new(HealthState::new())),
        &consent,
    );
    planes.calls = Arc::new(journal::call_records::CallRecords::open(
        Box::new(FailingStorage {
            inner: journal::call_records::InMemoryCallRecordStorage::new(),
            fail: fail.clone(),
        }),
        wall_clock_ms(),
    ));
    bind_held(&planes).await;
    assert_held(
        &decode(exchange(&planes, 9, 3, grant_request(Some("failed-custody-key"))).await),
        "consent",
    );
    fail.store(true, Ordering::SeqCst);
    consent.feed(json!([answered("failed-custody", "allow_30m")]));
    let _ = exchange(
        &planes,
        9,
        4,
        json!({"name":"late_results","arguments":{"since":null}}),
    )
    .await;
    assert!(consent
        .methods()
        .iter()
        .any(|method| method == cingulate_client::wire::CONSENT_ANSWERS));
    assert!(
        !consent
            .methods()
            .iter()
            .any(|method| method == cingulate_client::wire::CONSENT_ACK),
        "an answer cannot be acknowledged before the promised late result is durable"
    );
    assert!(
        planes.consent.raised("failed-custody").unwrap().applied,
        "the grant is stored before its late result"
    );
}

#[tokio::test]
async fn ending_the_head_scope_settles_consent_locally_without_opening_cingulate() {
    let consent = tests::ScriptedConsent::new();
    detach(&consent, "ended-card");
    let planes = attach_consent(
        isolated_test_planes(&Arc::new(HealthState::new())),
        &consent,
    );
    bind_held(&planes).await;
    assert_held(
        &decode(exchange(&planes, 9, 3, grant_request(Some("ended-key"))).await),
        "consent",
    );
    let before = consent.methods();
    revoke_scope(
        &planes,
        &std::collections::BTreeSet::from(["head-conversation".into()]),
    )
    .await;
    assert!(
        !planes.calls.has_pending_consents(),
        "ending the head scope must settle every held consent obligation"
    );
    let entries = late(&planes, 9).await;
    assert_eq!(
        entries["entries"][0]["detail"]["consent"], "withdrawn",
        "{entries}"
    );
    assert_eq!(entries["entries"][0]["kind"], "not_started");
    assert!(!planes.calls.has_pending_consents());
    assert_eq!(
        consent.methods(),
        before,
        "an ended session cannot open a route to Cingulate"
    );
}

#[test]
fn a_late_custody_write_cannot_reopen_ended_consent() {
    use journal::call_records::{Begin, CallRecords, ScopeIdentity};
    let calls = CallRecords::in_memory();
    assert!(matches!(
        calls.begin_scoped(
            "reserved:basal",
            "ending-key",
            "head-conversation",
            Some(ScopeIdentity::from_stamp(&run_stamp())),
            1
        ),
        Begin::Execute(_)
    ));
    calls
        .end_consent_conversation("head-conversation", 2)
        .unwrap();
    assert!(calls
        .hold_consent("reserved:basal", "ending-key", "too-late-card", 3)
        .is_err());
    assert!(!calls.has_pending_consents());
}
