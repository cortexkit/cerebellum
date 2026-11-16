//! App and takeover grants, and the consent a computer call waits for.
//!
//! Driven through `ComputerPlane::serve` -- the boundary the wire route calls
//! -- and through the management plane's grant admission, with the person's
//! answers scripted. Journals and grant stores are held in memory throughout.

use super::support;
use crate::support::HANG_GUARD;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use cerebellum::agent_grants::{
    AgentGrantStorage, AgentGrantStoreError, AgentGrantStoreState, FilesystemAgentGrantStorage,
    InMemoryAgentGrantStorage, AGENT_GRANT_STORE_FORMAT,
};
use cerebellum::cingulate_client::ScriptedAnswer;
use cerebellum::computer_capability::{servable, ComputerPlane, ServeContext};
use cerebellum::computer_grants::{
    AlwaysGrantRecord, AppIdentity, AppIdentityUnreadable, ComputerGrants, ConsentContext,
    ConsentRefusal, FilesystemGrantStorage, GrantCaller, GrantNeed, GrantStorage, GrantStoreState,
    InMemoryGrantStorage, QuestionCarrier, GRANT_STORE_VERSION,
};
use cerebellum::management::{ManagementPlane, TargetResolver};
use cerebellum_computer::capture::InMemoryCaptureBackend;
use cerebellum_computer::platform::{
    AccessibilityTreeRequest, AccessibilityTreeResult, AttendancePreconditionRequest,
    AttendancePreconditionResult, CapabilityAdvertisementContext, CapabilityDeclaration,
    DispatchResult, DriverError, EffectObservationRequest, EffectObservationResult, EffectStatus,
    ElementResolutionRequest, ElementResolutionResult, FocusQueryRequest, FocusQueryResult,
    FrontingSnapshot, InputObservationRequest, InputObservationResult, InputObserverLiveness,
    PlatformDriver, ProcessGrant, SemanticDispatchRequest, SyntheticDispatchRequest,
    TargetResolution,
};
use cerebellum_core::clock::FakeClock;
use cerebellum_core::journal::{InMemoryJournalStorage, ValidatedSeverityTaxonomy};
use serde_json::{json, Value};
use support::computer::{
    audit, grant, identity, team_identity, Fixed, FixedWithCode, InjectedCode, ScriptedCarrier,
    TestRedactor, FIXTURE_TEAM, GRANTEE,
};

const APP: &str = "com.apple.Safari";
const MACHINE: &str = "11111111-2222-3333-4444-555555555555";
const OTHER_MACHINE: &str = "99999999-8888-7777-6666-555555555555";

/// A platform driver that counts the keystroke dispatches it is asked for and
/// accepts each one. The count is what shows whether a refused call posted.
#[derive(Clone, Default)]
struct CountingDriver(Arc<Mutex<Vec<SyntheticDispatchRequest>>>);

impl PlatformDriver for CountingDriver {
    fn capability_declarations(
        &self,
        _context: &CapabilityAdvertisementContext,
    ) -> Vec<CapabilityDeclaration> {
        Vec::new()
    }
    fn read_accessibility_tree(
        &mut self,
        _request: AccessibilityTreeRequest,
    ) -> Result<AccessibilityTreeResult, DriverError> {
        Err(DriverError::Unsupported("test reads no tree"))
    }
    fn resolve_element(
        &mut self,
        _request: ElementResolutionRequest,
    ) -> Result<ElementResolutionResult, DriverError> {
        Err(DriverError::Unsupported("test resolves no element"))
    }
    fn dispatch_semantic(
        &mut self,
        _request: SemanticDispatchRequest,
    ) -> Result<DispatchResult, DriverError> {
        Err(DriverError::Unsupported(
            "test dispatches nothing semantically",
        ))
    }
    fn dispatch_per_pid(
        &mut self,
        request: SyntheticDispatchRequest,
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<DispatchResult, DriverError> {
        self.0.lock().unwrap().push(request);
        Ok(DispatchResult {
            accepted_by_platform: true,
            effect_status: EffectStatus::EffectIndeterminate,
            unreadable_subtrees: 0,
            delivery_posts_returned: 1,
            delivery_generation_verifications: 2,
        })
    }
    fn dispatch_global(
        &mut self,
        _request: cerebellum_computer::platform::GlobalDispatchRequest,
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<DispatchResult, DriverError> {
        Err(DriverError::Unsupported("test posts nothing globally"))
    }
    fn query_focus(
        &mut self,
        _request: FocusQueryRequest,
    ) -> Result<FocusQueryResult, DriverError> {
        Ok(FocusQueryResult {
            matches_target: true,
        })
    }
    fn fronting_snapshot(
        &mut self,
        _target: &ProcessGrant,
    ) -> Result<FrontingSnapshot, DriverError> {
        Err(DriverError::Unsupported("test captures no fronting state"))
    }
    fn input_observer_liveness(&self) -> InputObserverLiveness {
        InputObserverLiveness {
            session_tap_live: true,
            raw_hid_live: true,
            self_echo_filter_live: true,
        }
    }
    fn observe_input(
        &mut self,
        _request: InputObservationRequest,
    ) -> Result<InputObservationResult, DriverError> {
        Ok(InputObservationResult {
            human_or_ambiguous_input: false,
            detection_latency_ms: 1,
        })
    }
    fn observe_effect(
        &mut self,
        _request: EffectObservationRequest,
    ) -> Result<EffectObservationResult, DriverError> {
        Ok(EffectObservationResult {
            status: EffectStatus::EffectIndeterminate,
            failure_reason: Some("post_condition_undeclarable".to_string()),
        })
    }
    fn verify_attendance(
        &mut self,
        _request: AttendancePreconditionRequest,
    ) -> Result<AttendancePreconditionResult, DriverError> {
        Ok(AttendancePreconditionResult {
            valid: true,
            lease_generation: Some("lease-1".to_string()),
            age_ms: Some(1),
        })
    }
}

type TestPlane = ComputerPlane<
    InMemoryCaptureBackend,
    TestRedactor,
    ValidatedSeverityTaxonomy,
    InMemoryJournalStorage,
    CountingDriver,
>;

/// A plane whose target is frontmost with a plain text field focused, so a
/// keystroke call that is admitted reaches the driver.
fn plane(driver: &CountingDriver) -> TestPlane {
    let driver = driver.clone();
    ComputerPlane::with_synthetic_driver(audit(), move || driver.clone())
        .with_permission_liveness(super::support::computer::live_permissions())
        .with_app_state_source(support::computer::focused_text_desk().source())
}

fn caller(conversation: &str, attested: bool) -> GrantCaller {
    GrantCaller::new(conversation.to_string(), GRANTEE.to_string(), attested)
}

/// A consent context asking through `carrier`, whose route never closes and
/// whose module never drains.
fn asking(carrier: &ScriptedCarrier, caller: GrantCaller) -> ConsentContext {
    let (drain_sender, drain) = tokio::sync::watch::channel(false);
    // Kept alive for the process: a dropped sender would end the drain watch.
    std::mem::forget(drain_sender);
    ConsentContext::new(
        caller,
        Some(Arc::new(carrier.clone()) as Arc<dyn QuestionCarrier>),
        Arc::new(cerebellum::computer_grants::AlwaysOpenRoute),
        drain,
        None,
    )
}

fn management_over(grants: ComputerGrants) -> Arc<ManagementPlane> {
    Arc::new(ManagementPlane::with_computer_grants(
        Arc::new(Fixed(TargetResolution::Resolved(grant()))),
        Arc::new(grants),
    ))
}

fn in_memory_management() -> Arc<ManagementPlane> {
    management_over(ComputerGrants::in_memory())
}

fn agent_grants_over(storage: Arc<dyn AgentGrantStorage>) -> ComputerGrants {
    ComputerGrants::in_memory().with_agent_grants(support::permissions::store(
        storage,
        MACHINE,
        Arc::new(cerebellum::browser_standing_grants::SystemWallClock),
    ))
}

async fn serve(
    plane: &TestPlane,
    capability: &str,
    arguments: Value,
    management: &Arc<ManagementPlane>,
    consent: ConsentContext,
) -> Value {
    let clock = FakeClock::new();
    plane
        .serve(
            servable(capability).expect("the capability is served"),
            &arguments,
            ServeContext {
                cancel: cerebellum::CancelHandle::pending(),
                grantee: GRANTEE,
                identity: identity(),
                management,
                consent,
                clock: &clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await
        .expect("detect-only validation preserves the reply")
}

fn type_request() -> Value {
    json!({"target": APP, "text": "hi"})
}

fn decisions(question: &Value) -> Vec<String> {
    question["params"]["options"]
        .as_array()
        .expect("the question offers its decisions")
        .iter()
        .map(|option| option["id"].as_str().unwrap().to_string())
        .collect()
}

fn answer(decision: &str) -> ScriptedAnswer {
    ScriptedAnswer::Answered(json!({"decision": decision}))
}

async fn until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(HANG_GUARD, async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the condition came true");
}

fn app_need() -> GrantNeed {
    GrantNeed::App {
        bundle_identity: APP.to_string(),
        display_name: APP.to_string(),
        code: Arc::new(InjectedCode::default()),
    }
}

/// One app permission covers the same agent across conversations and returns
/// the waiting call's real result. A different agent needs a separate answer.
#[tokio::test]
async fn one_question_per_app_per_holder_survives_conversation_changes() {
    let driver = CountingDriver::default();
    let plane = plane(&driver);
    let management = in_memory_management();
    let carrier = ScriptedCarrier::default();

    let answering = {
        let carrier = carrier.clone();
        async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            assert!(carrier.answer_next(answer("allow_30m")));
        }
    };
    let (reply, ()) = tokio::join!(
        serve(
            &plane,
            "computer.type",
            type_request(),
            &management,
            asking(&carrier, caller("conversation-1", false)),
        ),
        answering
    );
    assert_eq!(reply["outcome"], "delivery_unconfirmed", "{reply}");
    assert_eq!(
        driver.0.lock().unwrap().len(),
        1,
        "the answered call posted"
    );

    let questions = carrier.questions();
    assert_eq!(questions.len(), 1);
    let params = &questions[0]["params"];
    assert_eq!(params["target"]["kind"], "app");
    // No running name can be read in a test, so the bundle identity is shown.
    assert_eq!(params["target"]["label"], APP);
    assert_eq!(
        decisions(&questions[0]),
        ["allow_30m", "computer_30m", "computer_always", "deny"]
    );

    let keys = serve(
        &plane,
        "computer.keys",
        json!({"target": APP, "keys": ["s"]}),
        &management,
        asking(&carrier, caller("conversation-1", false)),
    )
    .await;
    assert_eq!(keys["outcome"], "delivery_unconfirmed", "{keys}");
    let again = serve(
        &plane,
        "computer.type",
        type_request(),
        &management,
        asking(&carrier, caller("conversation-1", false)),
    )
    .await;
    assert_eq!(again["outcome"], "delivery_unconfirmed", "{again}");
    let waited = serve(
        &plane,
        "computer.wait",
        json!({
            "app": APP,
            "predicate": {"kind": "element_present", "element": {"Identifier": "ready"}},
            "timeout_ms": 0,
        }),
        &management,
        asking(&carrier, caller("conversation-1", false)),
    )
    .await;
    assert!(
        !waited["outcome"]
            .as_str()
            .unwrap_or_default()
            .starts_with("consent_"),
        "the app grant did not admit the wait: {waited}"
    );
    assert_eq!(
        carrier.questions().len(),
        1,
        "a second question was raised for an application already granted"
    );

    carrier.queue(answer("allow_30m"));
    let elsewhere = serve(
        &plane,
        "computer.type",
        type_request(),
        &management,
        asking(&carrier, caller("conversation-2", false)),
    )
    .await;
    assert_eq!(elsewhere["outcome"], "delivery_unconfirmed", "{elsewhere}");
    assert_eq!(
        carrier.questions().len(),
        1,
        "the same head's row did not cover another conversation"
    );
    let another_head = GrantCaller::new("conversation-3".into(), "another-head".into(), false);
    let separate = serve(
        &plane,
        "computer.type",
        type_request(),
        &management,
        asking(&carrier, another_head),
    )
    .await;
    assert_eq!(separate["outcome"], "delivery_unconfirmed", "{separate}");
    assert_eq!(
        carrier.questions().len(),
        2,
        "another head borrowed this head's grant"
    );
}

/// A call not answered inside its wait returns `consent_pending` with the ask
/// and a remedy that promises a wake. The question stays open, and an answer
/// that arrives afterwards still writes the grant.
#[tokio::test]
async fn an_unanswered_wait_is_consent_pending_and_a_later_answer_still_grants() {
    let driver = CountingDriver::default();
    let plane = plane(&driver);
    let management = in_memory_management();
    let carrier = ScriptedCarrier::default();
    let consent = asking(&carrier, caller("conversation-1", false))
        .with_park_limit(Duration::from_millis(50));

    let reply = serve(
        &plane,
        "computer.type",
        type_request(),
        &management,
        consent,
    )
    .await;
    assert_eq!(reply["outcome"], "consent_pending", "{reply}");
    let ask_id = reply["ask_id"]
        .as_str()
        .expect("the ask is named")
        .to_string();
    assert_eq!(
        reply["remedy"],
        "The person has been asked. You will be woken when they answer; then retry this call."
    );
    assert!(driver.0.lock().unwrap().is_empty(), "a pending call posted");
    assert!(
        management.computer_grants().question_open(&ask_id),
        "the question closed with the wait"
    );

    assert!(carrier.answer_next(answer("allow_30m")));
    let grants = Arc::clone(management.computer_grants());
    carrier.apply_late(management.computer_grants()).await;
    until(|| grants.holds(&caller("conversation-1", false), &app_need())).await;

    let retried = serve(
        &plane,
        "computer.type",
        type_request(),
        &management,
        asking(&carrier, caller("conversation-1", false)),
    )
    .await;
    assert_eq!(retried["outcome"], "delivery_unconfirmed", "{retried}");
    assert_eq!(carrier.questions().len(), 1, "the retry asked again");
}

/// A deny is remembered for the conversation: the next call refuses at once
/// and no new question reaches the person.
#[tokio::test]
async fn a_deny_is_remembered_and_the_next_call_is_refused_without_asking() {
    let driver = CountingDriver::default();
    let plane = plane(&driver);
    let management = in_memory_management();
    let carrier = ScriptedCarrier::answering(&["deny"]);

    let denied = serve(
        &plane,
        "computer.type",
        type_request(),
        &management,
        asking(&carrier, caller("conversation-1", false)),
    )
    .await;
    assert_eq!(denied["outcome"], "consent_denied", "{denied}");
    assert_eq!(denied["bundle_identity"], APP);

    let again = serve(
        &plane,
        "computer.type",
        type_request(),
        &management,
        asking(&carrier, caller("conversation-1", false)),
    )
    .await;
    assert_eq!(again["outcome"], "consent_denied", "{again}");
    assert_eq!(again["reason"], "denied_earlier_in_this_conversation");
    assert!(again["remedy"]
        .as_str()
        .is_some_and(|remedy| remedy.contains("Ask them in chat")));
    assert_eq!(
        carrier.questions().len(),
        1,
        "a refused app was asked again"
    );
    assert!(driver.0.lock().unwrap().is_empty(), "a refused call posted");
}

async fn admit(
    management: &ManagementPlane,
    carrier: &ScriptedCarrier,
    caller: GrantCaller,
) -> Result<cerebellum::computer_grants::GrantAdmission, Value> {
    management
        .admit_app(
            APP,
            &asking(carrier, caller),
            &cerebellum::CancelHandle::pending(),
        )
        .await
        .map(|(_, admission)| admission)
        .map_err(|refusal| refusal.reply(APP))
}

/// An "always" answer lasts until revoked and survives reopening the agent store.
#[tokio::test]
async fn an_always_answer_survives_a_module_restart() {
    let storage = InMemoryAgentGrantStorage::default();
    let first = management_over(agent_grants_over(Arc::new(storage.clone())));
    let carrier = ScriptedCarrier::answering(&["allow_always"]);
    let admission = admit(&first, &carrier, caller("conversation-1", true))
        .await
        .expect("the always answer admits the call");
    let questions = carrier.questions();
    let params = &questions[0]["params"];
    assert_eq!(params["kind"], "consent");
    assert_eq!(params["default"], "deny");
    assert_eq!(params["on_expiry"], "deny");
    assert_eq!(params["urgency"], "high");
    assert_eq!(params["scope"]["app"], APP);
    assert!(params.get("duration").is_none());
    assert_eq!(
        decisions(&questions[0]),
        [
            "allow_30m",
            "allow_always",
            "computer_30m",
            "computer_always",
            "deny"
        ]
    );
    assert_eq!(
        params["options"][0]["label"],
        format!("Use {APP} for 30 minutes")
    );
    assert_eq!(params["options"][1]["label"], format!("Always allow {APP}"));
    assert_eq!(params["options"][4]["effect"], "decline");
    assert_eq!(admission.persisted, Some(Ok(())));
    let mut reply = json!({"outcome":"completed"});
    admission.decorate(&mut reply);
    assert_eq!(reply["grant_persisted"], true);
    let stored = storage.load().unwrap().unwrap();
    assert_eq!(stored.version, AGENT_GRANT_STORE_FORMAT.version);
    assert_eq!(stored.grants.len(), 1);
    assert_eq!(stored.grants[0].machine_uuid, MACHINE);
    assert_eq!(stored.grants[0].holder.agent_id(), GRANTEE);
    assert_eq!(stored.grants[0].expires_at_ms, None);
    let restarted = management_over(agent_grants_over(Arc::new(storage)));
    let silent = ScriptedCarrier::default();
    admit(&restarted, &silent, caller("conversation-9", true))
        .await
        .expect("the stored always grant admits a new conversation");
    assert!(
        silent.questions().is_empty(),
        "the restarted module asked again"
    );
}

/// A foreign-machine record is inert and hidden from the local inventory.
/// A restored backup cannot lend another machine's permission.
#[tokio::test]
async fn a_record_naming_another_machine_grants_nothing() {
    let storage = InMemoryGrantStorage::new();
    storage
        .save(&GrantStoreState {
            version: GRANT_STORE_VERSION,
            records: vec![AlwaysGrantRecord {
                agent_project_id: GRANTEE.to_string(),
                bundle_identity: APP.to_string(),
                team_id: Some(FIXTURE_TEAM.to_string()),
                designated_requirement: Some(team_identity(FIXTURE_TEAM).designated_requirement),
                machine_uuid: OTHER_MACHINE.to_string(),
                created_at_ms: 1,
            }],
        })
        .unwrap();
    let management = management_over(ComputerGrants::open(
        Arc::new(storage),
        Some(MACHINE.to_string()),
    ));
    let carrier = ScriptedCarrier::answering(&["deny"]);
    let refused = admit(&management, &carrier, caller("conversation-1", true)).await;
    assert_eq!(
        carrier.questions().len(),
        1,
        "a record from another machine admitted the call without asking"
    );
    assert_eq!(refused.unwrap_err()["outcome"], "consent_denied");

    let listing = management.computer_grants().list();
    assert_eq!(listing["grants"], json!([]));
    assert_eq!(
        listing["other_machine_grants"],
        json!([]),
        "foreign-machine rows are hidden as well as inert"
    );
}

/// "Always" is offered only to a bind whose agent and session kind the daemon
/// attested; an unattested bind cannot store or use a durable grant.
#[tokio::test]
async fn an_unattested_bind_is_not_offered_always() {
    let storage = InMemoryGrantStorage::new();
    let management = management_over(ComputerGrants::open(
        Arc::new(storage.clone()),
        Some(MACHINE.into()),
    ));

    let unattested = ScriptedCarrier::answering(&["allow_always"]);
    let refused = admit(&management, &unattested, caller("conversation-1", false)).await;
    assert_eq!(
        decisions(&unattested.questions()[0]),
        ["allow_30m", "computer_30m", "computer_always", "deny"],
        "an unattested bind was offered always"
    );
    // An answer the question did not offer is consent to nothing.
    assert_eq!(refused.unwrap_err()["reason"], "unrecognized_answer");
    assert!(storage.load().unwrap().records.is_empty());

    let attested = ScriptedCarrier::answering(&["deny"]);
    let _ = admit(&management, &attested, caller("conversation-2", true)).await;
    assert_eq!(
        decisions(&attested.questions()[0]),
        [
            "allow_30m",
            "allow_always",
            "computer_30m",
            "computer_always",
            "deny"
        ]
    );
}

fn scratch_directory(label: &str) -> std::path::PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "cerebellum-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

/// Unreadable unified storage withholds all grants and is never overwritten.
#[tokio::test]
async fn a_corrupt_store_fails_closed_and_is_disclosed() {
    let directory = scratch_directory("corrupt-grants");
    let path = directory.join("agent-grants.json");
    std::fs::write(&path, b"{ not json").unwrap();
    let grants = agent_grants_over(Arc::new(FilesystemAgentGrantStorage::new(&path)));
    assert!(matches!(
        grants.agent_grants().store_error(),
        Some(AgentGrantStoreError::Corrupt { .. })
    ));
    let listing = grants.list();
    assert_eq!(listing["store"]["state"], "unreadable");
    assert_eq!(listing["store"]["reason"], "grant_store_unreadable");
    assert_eq!(
        grants.revoke(GRANTEE, APP, false)["outcome"],
        "store_unavailable"
    );
    let management = management_over(grants);
    let carrier = ScriptedCarrier::answering(&["allow_30m"]);
    let refused = admit(&management, &carrier, caller("conversation-1", true))
        .await
        .unwrap_err();
    assert_eq!(refused["reason"], "unrecognized_answer");
    assert_eq!(
        decisions(&carrier.questions()[0]),
        ["allow_once", "deny"],
        "always was offered over a store that could not be read"
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"{ not json");
    let newer_version = AGENT_GRANT_STORE_FORMAT.version + 1;
    std::fs::write(
        &path,
        format!(r#"{{"version": {newer_version}, "grants": []}}"#),
    )
    .unwrap();
    let newer = agent_grants_over(Arc::new(FilesystemAgentGrantStorage::new(&path)));
    assert_eq!(
        newer.agent_grants().store_error(),
        Some(AgentGrantStoreError::UnknownVersion {
            found: newer_version
        })
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// Storage whose writes always fail.
struct UnwritableStorage;

impl AgentGrantStorage for UnwritableStorage {
    fn load(&self) -> Result<Option<AgentGrantStoreState>, AgentGrantStoreError> {
        Ok(None)
    }
    fn save(&self, _state: &AgentGrantStoreState) -> Result<(), AgentGrantStoreError> {
        Err(AgentGrantStoreError::WriteFailed {
            detail: "read-only file system".into(),
        })
    }
}

/// A failed durable write must not create an unrevocable conversation fallback.
#[tokio::test]
async fn a_failed_always_write_refuses_without_dispatch_or_fallback_grant() {
    let driver = CountingDriver::default();
    let plane = plane(&driver);
    let management = management_over(agent_grants_over(Arc::new(UnwritableStorage)));
    let carrier = ScriptedCarrier::answering(&["allow_always", "allow_always"]);
    for _ in 0..2 {
        let reply = serve(
            &plane,
            "computer.type",
            type_request(),
            &management,
            asking(&carrier, caller("conversation-1", true)),
        )
        .await;
        assert_eq!(reply["outcome"], "consent_unavailable", "{reply}");
        assert_eq!(reply["reason"], "grant_not_recorded", "{reply}");
        assert!(driver.0.lock().unwrap().is_empty());
        assert_eq!(management.computer_grants().list()["grants"], json!([]));
    }
    assert_eq!(
        carrier.questions().len(),
        2,
        "failed writes cannot admit a retry"
    );
}

/// Storage whose writes take long enough that a call released early would be
/// seen acting before the write finished.
#[derive(Clone, Default)]
struct SlowStorage(InMemoryAgentGrantStorage);

impl AgentGrantStorage for SlowStorage {
    fn load(&self) -> Result<Option<AgentGrantStoreState>, AgentGrantStoreError> {
        self.0.load()
    }
    fn save(&self, state: &AgentGrantStoreState) -> Result<(), AgentGrantStoreError> {
        std::thread::sleep(Duration::from_millis(300));
        self.0.save(state)
    }
}

/// The grant, and for "always" the store record, is written before the
/// waiting call is released: the call that the answer released always finds
/// the grant it was released for, and the record is on disk when it acts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_always_answer_is_stored_before_the_waiting_call_is_released() {
    let driver = CountingDriver::default();
    let plane = plane(&driver);
    let storage = SlowStorage::default();
    let management = management_over(agent_grants_over(Arc::new(storage.clone())));
    let carrier = ScriptedCarrier::answering(&["allow_always"]);
    let reply = serve(
        &plane,
        "computer.type",
        type_request(),
        &management,
        asking(&carrier, caller("conversation-1", true)),
    )
    .await;
    assert_eq!(reply["outcome"], "delivery_unconfirmed", "{reply}");
    assert_eq!(reply["grant_persisted"], true, "{reply}");
    assert_eq!(
        storage.0.load().unwrap().unwrap().grants.len(),
        1,
        "the call acted before its always answer was stored"
    );
}

/// Takeover is asked separately with once and whole-computer choices; an app
/// permission alone never authorizes pointer or keyboard takeover.
#[tokio::test]
async fn takeover_is_asked_separately_and_no_app_grant_satisfies_it() {
    let grants = Arc::new(ComputerGrants::open(
        Arc::new(InMemoryGrantStorage::new()),
        Some(MACHINE.to_string()),
    ));
    let management = Arc::new(ManagementPlane::with_computer_grants(
        Arc::new(Fixed(TargetResolution::Resolved(grant()))),
        Arc::clone(&grants),
    ));
    let carrier = ScriptedCarrier::answering(&["allow_30m", "computer_30m"]);
    let attested = caller("conversation-1", true);
    admit(&management, &carrier, attested.clone())
        .await
        .expect("the app grant is answered");
    assert!(grants.holds(&attested, &app_need()));
    assert!(
        !grants.holds(&attested, &GrantNeed::Takeover),
        "an app grant satisfied the takeover"
    );

    grants
        .require(
            &GrantNeed::Takeover,
            &asking(&carrier, attested.clone()),
            &cerebellum::CancelHandle::pending(),
        )
        .await
        .expect("the takeover answer admits");
    let questions = carrier.questions();
    assert_eq!(questions.len(), 2, "takeover was not asked on its own");
    let takeover = &questions[1];
    assert_eq!(takeover["params"]["target"]["kind"], "machine");
    assert_eq!(takeover["params"]["urgency"], "high");
    assert_eq!(takeover["params"]["scope"], json!({"takeover": "machine"}));
    assert_eq!(
        decisions(takeover),
        ["allow_once", "computer_30m", "computer_always", "deny"]
    );
    assert!(takeover["params"].get("app").is_none());
    // Pinned byte for byte: the apps show these unchanged. The headline asks the
    // question; the Covers row has to name both uses of the grant, fronting an
    // application for keystrokes and driving the real pointer.
    assert_eq!(
        takeover["params"]["prompt"],
        "Let the agent control your mouse and keyboard?"
    );
    let fact = |label: &str| {
        takeover["params"]["facts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|fact| fact["label"] == label)
            .map(|fact| fact["value"].clone())
    };
    assert_eq!(
        fact("Covers"),
        Some(json!("Bringing apps to the front, typing into them and moving your real pointer, in any app on the screen."))
    );
    assert_eq!(
        fact("To stop"),
        Some(json!("Touch your mouse or keyboard."))
    );
    assert!(grants.holds(&attested, &GrantNeed::Takeover));
    assert!(grants.holds(&caller("conversation-2", true), &GrantNeed::Takeover));
    assert!(!grants.holds(
        &GrantCaller::new("another".into(), "another-head".into(), true),
        &GrantNeed::Takeover
    ));
}

/// An "always" answer to a takeover question grants nothing: the question
/// never offered it.
#[tokio::test]
async fn an_always_answer_to_a_takeover_question_grants_nothing() {
    let grants = Arc::new(ComputerGrants::open(
        Arc::new(InMemoryGrantStorage::new()),
        Some(MACHINE.to_string()),
    ));
    let carrier = ScriptedCarrier::answering(&["allow_always"]);
    let refused = grants
        .require(
            &GrantNeed::Takeover,
            &asking(&carrier, caller("conversation-1", true)),
            &cerebellum::CancelHandle::pending(),
        )
        .await
        .unwrap_err();
    assert!(matches!(refused, ConsentRefusal::Unavailable { .. }));
    assert!(!grants.holds(&caller("conversation-1", true), &GrantNeed::Takeover));
}

/// Two submitted calls on one app raise one question. The first holds the
/// app's FIFO lane while asking; the second runs later under the recorded
/// conversation grant, rather than joining the first call's consent wait.
#[tokio::test]
async fn two_concurrent_calls_raise_exactly_one_question() {
    let driver = CountingDriver::default();
    let plane = plane(&driver);
    let management = in_memory_management();
    let carrier = ScriptedCarrier::default();
    let answering = {
        let carrier = carrier.clone();
        async move {
            until(|| carrier.questions().len() == 1).await;
            // Let the second call reach the app queue before answering.
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(carrier.answer_next(answer("allow_30m")));
        }
    };
    let (first, second, ()) = tokio::join!(
        serve(
            &plane,
            "computer.type",
            type_request(),
            &management,
            asking(&carrier, caller("conversation-1", false)),
        ),
        serve(
            &plane,
            "computer.keys",
            json!({"target": APP, "keys": ["s"]}),
            &management,
            asking(&carrier, caller("conversation-1", false)),
        ),
        answering
    );
    assert_eq!(carrier.questions().len(), 1, "two questions for one grant");
    let mut outcomes = vec![
        first["outcome"].as_str().unwrap().to_string(),
        second["outcome"].as_str().unwrap().to_string(),
    ];
    outcomes.sort();
    assert_eq!(outcomes, ["delivery_unconfirmed", "delivery_unconfirmed"]);
    let dispatched = driver.0.lock().unwrap();
    assert_eq!(
        dispatched.len(),
        2,
        "both queued calls run under the app grant"
    );
    assert!(matches!(
        dispatched[0].action,
        cerebellum_computer::platform::SyntheticAction::TypeText { .. }
    ));
    assert!(matches!(
        dispatched[1].action,
        cerebellum_computer::platform::SyntheticAction::KeyCombination { .. }
    ));
}

/// The app revoke operation uses the same store as dispatch authorization;
/// dry-run counts the matching rows without changing them.
#[tokio::test]
async fn a_revoked_always_grant_is_asked_for_again() {
    let storage = InMemoryAgentGrantStorage::default();
    let management = management_over(agent_grants_over(Arc::new(storage.clone())));
    let carrier = ScriptedCarrier::answering(&["allow_always", "deny"]);
    admit(&management, &carrier, caller("conversation-1", true))
        .await
        .expect("the always answer admits");
    let grants = management.computer_grants();
    assert_eq!(
        grants.revoke(GRANTEE, APP, true),
        json!({"outcome":"would_revoke","records":1})
    );
    assert_eq!(storage.load().unwrap().unwrap().grants.len(), 1);
    assert_eq!(
        grants.revoke(GRANTEE, APP, false),
        json!({"outcome":"revoked","records":1})
    );
    assert!(storage.load().unwrap().unwrap().grants.is_empty());
    assert_eq!(
        grants.revoke(GRANTEE, APP, false)["outcome"],
        "grant_not_found"
    );
    let _ = admit(&management, &carrier, caller("conversation-1", true)).await;
    assert_eq!(
        carrier.questions().len(),
        2,
        "a revoked grant still admitted the call"
    );
}

/// The carrier's words for "nobody was asked" and "nobody answered" end the
/// question honestly: neither is reported as pending, and the next call asks
/// again rather than waiting on a question that is over.
#[tokio::test]
async fn nobody_asked_and_nobody_answered_are_not_reported_as_pending() {
    let driver = CountingDriver::default();
    let plane = plane(&driver);
    let management = in_memory_management();
    let carrier = ScriptedCarrier::default();
    carrier.queue(ScriptedAnswer::NotPutToAnyone);
    carrier.queue(ScriptedAnswer::NoAnswer);

    let unreached = serve(
        &plane,
        "computer.type",
        type_request(),
        &management,
        asking(&carrier, caller("conversation-1", false)),
    )
    .await;
    assert_eq!(unreached["outcome"], "consent_unavailable", "{unreached}");
    assert_eq!(unreached["reason"], "not_put_to_anyone", "{unreached}");
    assert_eq!(
        unreached["remedy"],
        "Nobody could be asked: the question was shown to no one, and the next call's question reaches no one either until the caller's consent route can put it to a person."
    );

    let unanswered = serve(
        &plane,
        "computer.type",
        type_request(),
        &management,
        asking(&carrier, caller("conversation-1", false)),
    )
    .await;
    assert_eq!(unanswered["outcome"], "consent_unavailable", "{unanswered}");
    assert_eq!(unanswered["reason"], "no_answer", "{unanswered}");
    assert_eq!(
        carrier.questions().len(),
        2,
        "the second call did not ask again"
    );
    assert!(driver.0.lock().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// App grants are bound to the application's code-signing identity
// ---------------------------------------------------------------------------

/// A plane whose application's signature is `code`, over grants that can
/// offer "always" on this machine.
fn signed_management(code: &InjectedCode, storage: &InMemoryGrantStorage) -> Arc<ManagementPlane> {
    Arc::new(ManagementPlane::with_computer_grants(
        Arc::new(FixedWithCode(
            TargetResolution::Resolved(grant()),
            code.clone(),
        )),
        Arc::new(ComputerGrants::open(
            Arc::new(storage.clone()),
            Some(MACHINE.to_string()),
        )),
    ))
}

fn need_for(code: &InjectedCode) -> GrantNeed {
    GrantNeed::App {
        bundle_identity: APP.to_string(),
        display_name: APP.to_string(),
        code: Arc::new(code.clone()),
    }
}

fn question_message(question: &Value) -> String {
    question["params"]["facts"].to_string()
}

const SIGNATURE_CHANGED: &str = "code signature has changed since it was approved";

/// Both grant lifetimes retain the verified app code-signing requirement and
/// admit that app for the same agent in later conversations without asking again.
#[tokio::test]
async fn the_signature_a_grant_was_made_for_is_admitted_without_asking_again() {
    for decision in ["allow_30m", "allow_always"] {
        let code = InjectedCode::default();
        let storage = InMemoryAgentGrantStorage::default();
        let management = signed_agent_management(&code, &storage);
        let carrier = ScriptedCarrier::answering(&[decision]);
        admit(&management, &carrier, caller("conversation-1", true))
            .await
            .expect("the granting answer admits");
        admit(&management, &carrier, caller("conversation-2", true))
            .await
            .expect("the same signature is admitted again");
        let stored = storage.load().unwrap().unwrap();
        assert_eq!(stored.grants.len(), 1);
        let expected = team_identity(FIXTURE_TEAM);
        assert_eq!(stored.grants[0].team_id, expected.team_id);
        assert_eq!(
            stored.grants[0].designated_requirement,
            Some(expected.designated_requirement)
        );
        assert_eq!(
            stored.grants[0].expires_at_ms.is_none(),
            decision == "allow_always"
        );
        assert_eq!(
            carrier.questions().len(),
            1,
            "the same holder and signature was asked again"
        );
    }
}

#[tokio::test]
async fn a_conversation_denial_wins_when_the_original_app_signature_returns() {
    for permanent in [false, true] {
        let code = InjectedCode::default();
        let storage = InMemoryAgentGrantStorage::default();
        let management = signed_agent_management(&code, &storage);
        let carrier = ScriptedCarrier::answering(&[
            if permanent {
                "allow_always"
            } else {
                "allow_30m"
            },
            "deny",
        ]);
        let owner = caller("conversation-1", permanent);
        admit(&management, &carrier, owner.clone()).await.unwrap();
        code.replace(Ok(team_identity("IMPOSTOR01")));
        let denied = admit(&management, &carrier, owner.clone())
            .await
            .unwrap_err();
        assert_eq!(denied["outcome"], "consent_denied", "{denied}");
        assert_eq!(carrier.questions().len(), 2);
        code.replace(Ok(team_identity(FIXTURE_TEAM)));
        let again = admit(&management, &carrier, owner.clone()).await;
        assert!(
            again.is_err(),
            "the original row overrode the conversation denial"
        );
        let again = again.unwrap_err();
        assert_eq!(again["reason"], "denied_earlier_in_this_conversation");
        assert!(!management.computer_grants().holds(&owner, &need_for(&code)));
        admit(&management, &carrier, caller("conversation-2", permanent))
            .await
            .expect("the denial must not revoke another conversation's standing grant");
        assert_eq!(carrier.questions().len(), 2);
        assert_eq!(storage.load().unwrap().unwrap().grants.len(), 1);
    }
}

/// A changed signer or designated code-signing requirement prompts again for
/// both lifetimes. Declining preserves the grant for the original app signature.
#[tokio::test]
async fn a_different_signature_under_the_same_bundle_identity_is_asked_again() {
    for permanent in [false, true] {
        let code = InjectedCode::default();
        let storage = InMemoryAgentGrantStorage::default();
        let management = signed_agent_management(&code, &storage);
        let grants = management.computer_grants();
        let decision = if permanent {
            "allow_always"
        } else {
            "allow_30m"
        };
        let carrier = ScriptedCarrier::answering(&[decision, "deny"]);
        let owner = caller("conversation-1", permanent);
        admit(&management, &carrier, owner.clone())
            .await
            .expect("the original code is approved");
        let mut replacement = team_identity(if permanent {
            FIXTURE_TEAM
        } else {
            "IMPOSTOR01"
        });
        if permanent {
            replacement.designated_requirement = format!("identifier \"com.example.Other\" and anchor apple generic and certificate leaf[subject.OU] = \"{FIXTURE_TEAM}\"");
        }
        code.replace(Ok(replacement));
        assert!(!grants.holds(&owner, &need_for(&code)));
        let refused = admit(&management, &carrier, owner.clone())
            .await
            .unwrap_err();
        assert_eq!(refused["outcome"], "consent_denied");
        let questions = carrier.questions();
        assert_eq!(
            questions.len(),
            2,
            "the changed signature was not asked about"
        );
        assert!(!question_message(&questions[0]).contains(SIGNATURE_CHANGED));
        assert!(question_message(&questions[1]).contains(SIGNATURE_CHANGED));
        let p = &questions[1]["params"];
        assert_eq!(p["kind"], "consent");
        assert_eq!(p["target"]["kind"], "app");
        assert_eq!(p["urgency"], "high");
        assert_eq!(
            p["scope"],
            json!({"app":APP,"team_id":if permanent { FIXTURE_TEAM } else { "IMPOSTOR01" }})
        );
        assert_eq!(p["default"], "deny");
        assert_eq!(p["on_expiry"], "deny");
        assert_eq!(p["expires_in_ms"], 1_800_000);
        let expected = if permanent {
            vec![
                "allow_30m",
                "allow_always",
                "computer_30m",
                "computer_always",
                "deny",
            ]
        } else {
            vec!["allow_30m", "computer_30m", "computer_always", "deny"]
        };
        assert_eq!(decisions(&questions[1]), expected);
        assert!(p.get("requestedSchema").is_none());
        for option in p["options"].as_array().unwrap() {
            assert_eq!(
                option["effect"],
                if option["id"] == "deny" {
                    "decline"
                } else {
                    "grant"
                }
            );
        }
        assert!(!grants.holds(&owner, &need_for(&code)));
        assert_eq!(
            storage.load().unwrap().unwrap().grants.len(),
            1,
            "the original record was lost"
        );
        code.replace(Ok(team_identity(FIXTURE_TEAM)));
        admit(&management, &carrier, caller("conversation-2", true))
            .await
            .expect("the original signature remains approved");
        assert_eq!(carrier.questions().len(), 2);
    }
}

/// A process whose signature cannot be read is refused with a declared
/// reason, whether it is being asked about or holds a grant already, and
/// nobody is asked about it.
#[tokio::test]
async fn an_unreadable_signature_is_refused_and_nobody_is_asked() {
    let unreadable = || {
        Err(AppIdentityUnreadable::Failed {
            detail: "fixture".to_string(),
        })
    };
    let code = InjectedCode::new(unreadable());
    let storage = InMemoryGrantStorage::new();
    let management = signed_management(&code, &storage);
    let carrier = ScriptedCarrier::answering(&["allow_30m"]);

    let refused = admit(&management, &carrier, caller("conversation-1", true))
        .await
        .unwrap_err();
    assert_eq!(refused["outcome"], "consent_unavailable", "{refused}");
    assert_eq!(refused["reason"], "app_identity_unreadable", "{refused}");
    assert!(
        carrier.questions().is_empty(),
        "an unreadable process was asked about"
    );

    code.replace(Ok(team_identity(FIXTURE_TEAM)));
    admit(&management, &carrier, caller("conversation-1", true))
        .await
        .expect("a readable signature is asked about and admitted");
    code.replace(unreadable());
    let refused = admit(&management, &carrier, caller("conversation-1", true))
        .await
        .unwrap_err();
    assert_eq!(refused["reason"], "app_identity_unreadable", "{refused}");
    assert_eq!(carrier.questions().len(), 1);
}

/// An ad-hoc signature names one build, and a signature with no Team ID that
/// Apple did not make names no lasting signer: neither is offered "always",
/// though each can be allowed for the conversation.
#[tokio::test]
async fn an_ad_hoc_or_teamless_application_is_not_offered_always() {
    let ad_hoc = AppIdentity {
        team_id: None,
        designated_requirement: "cdhash H\"0123456789abcdef0123456789abcdef01234567\"".to_string(),
        ad_hoc: true,
        apple_anchored: false,
    };
    let teamless = AppIdentity {
        team_id: None,
        designated_requirement: format!(
            "identifier \"{APP}\" and certificate root = H\"89abcdef89abcdef89abcdef89abcdef89abcdef\""
        ),
        ad_hoc: false,
        apple_anchored: false,
    };
    for (index, identity) in [ad_hoc, teamless].into_iter().enumerate() {
        let code = InjectedCode::new(Ok(identity));
        let storage = InMemoryGrantStorage::new();
        let management = signed_management(&code, &storage);
        let carrier = ScriptedCarrier::answering(&["allow_30m"]);
        let conversation = caller(&format!("conversation-{index}"), true);
        admit(&management, &carrier, conversation.clone())
            .await
            .expect("a conversation grant still works");
        assert_eq!(
            decisions(&carrier.questions()[0]),
            ["allow_30m", "computer_30m", "computer_always", "deny"],
            "always was offered to an application with no lasting signer"
        );
        assert!(management
            .computer_grants()
            .holds(&conversation, &need_for(&code)));
        assert!(storage.load().unwrap().records.is_empty());
    }
}

/// Apple-anchored apps keep their designated requirement without a Team ID.
#[tokio::test]
async fn an_apple_anchored_application_is_offered_always() {
    let code = InjectedCode::new(Ok(AppIdentity {
        team_id: None,
        designated_requirement: "identifier \"com.apple.TextEdit\" and anchor apple".into(),
        ad_hoc: false,
        apple_anchored: true,
    }));
    let storage = InMemoryAgentGrantStorage::default();
    let management = signed_agent_management(&code, &storage);
    let carrier = ScriptedCarrier::answering(&["allow_always"]);
    admit(&management, &carrier, caller("conversation-1", true))
        .await
        .expect("the always answer admits");
    assert_eq!(
        decisions(&carrier.questions()[0]),
        [
            "allow_30m",
            "allow_always",
            "computer_30m",
            "computer_always",
            "deny"
        ]
    );
    let stored = storage.load().unwrap().unwrap();
    assert_eq!(stored.grants[0].team_id, None);
    assert_eq!(
        stored.grants[0].designated_requirement.as_deref(),
        Some("identifier \"com.apple.TextEdit\" and anchor apple")
    );
}

/// A stored record that names no signature grants nothing, and the listing
/// reports it apart. A store written before signatures were recorded is a
/// version this build does not read, and is refused and disclosed.
#[tokio::test]
async fn a_record_without_a_signing_identity_grants_nothing() {
    let storage = InMemoryGrantStorage::new();
    storage
        .save(&GrantStoreState {
            version: GRANT_STORE_VERSION,
            records: vec![AlwaysGrantRecord {
                agent_project_id: GRANTEE.to_string(),
                bundle_identity: APP.to_string(),
                team_id: None,
                designated_requirement: None,
                machine_uuid: MACHINE.to_string(),
                created_at_ms: 1,
            }],
        })
        .unwrap();
    let code = InjectedCode::default();
    let management = signed_management(&code, &storage);
    let carrier = ScriptedCarrier::answering(&["deny"]);
    let refused = admit(&management, &carrier, caller("conversation-1", true)).await;
    assert_eq!(
        carrier.questions().len(),
        1,
        "a record naming no signature admitted the call without asking"
    );
    assert_eq!(refused.unwrap_err()["outcome"], "consent_denied");
    assert!(
        !question_message(&carrier.questions()[0]).contains(SIGNATURE_CHANGED),
        "a record naming no signature was reported as a changed signature"
    );
    let listing = management.computer_grants().list();
    assert_eq!(listing["grants"], json!([]));
    assert_eq!(listing["unbound_grants"][0]["bundle_identity"], APP);

    let directory = scratch_directory("version-one-grants");
    let path = directory.join("computer_grants.json");
    std::fs::write(
        &path,
        format!(
            r#"{{"version": 1, "records": [{{"agent_project_id": "{GRANTEE}",
                "bundle_identity": "{APP}", "machine_uuid": "{MACHINE}",
                "created_at_ms": 1}}]}}"#
        ),
    )
    .unwrap();
    let old = ComputerGrants::open(
        Arc::new(FilesystemGrantStorage::new(&path)),
        Some(MACHINE.to_string()),
    );
    assert!(matches!(
        old.agent_grants().store_error(),
        Some(AgentGrantStoreError::Legacy { store: "apps", .. })
    ));
    assert_eq!(old.list()["store"]["reason"], "grant_store_unreadable");
    let old = Arc::new(ManagementPlane::with_computer_grants(
        Arc::new(FixedWithCode(TargetResolution::Resolved(grant()), code)),
        Arc::new(old),
    ));
    let carrier = ScriptedCarrier::answering(&["deny"]);
    let _ = admit(&old, &carrier, caller("conversation-1", true)).await;
    assert_eq!(
        carrier.questions().len(),
        1,
        "a version 1 record admitted the call"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// A resolver with no signature reader, as on a platform that has none.
struct NoReaderResolver;

impl TargetResolver for NoReaderResolver {
    fn resolve(&self, _bundle_identity: &str) -> TargetResolution {
        TargetResolution::Resolved(grant())
    }
}

/// Where no code-signing identity can be read, every app grant is refused
/// with a reason naming that, before anyone is asked and before anything is
/// posted. The executable name such a platform resolves by can be claimed by
/// any program, so a grant keyed by it alone would be a grant to whoever
/// claims it.
#[tokio::test]
async fn a_platform_with_no_signature_reader_refuses_before_anything_is_posted() {
    let driver = CountingDriver::default();
    let plane = plane(&driver);
    let management = Arc::new(ManagementPlane::with_computer_grants(
        Arc::new(NoReaderResolver),
        Arc::new(ComputerGrants::open(
            Arc::new(InMemoryGrantStorage::new()),
            Some(MACHINE.to_string()),
        )),
    ));
    let carrier = ScriptedCarrier::answering(&["allow_always"]);
    let reply = serve(
        &plane,
        "computer.type",
        type_request(),
        &management,
        asking(&carrier, caller("conversation-1", true)),
    )
    .await;
    assert_eq!(reply["outcome"], "consent_unavailable", "{reply}");
    assert_eq!(reply["reason"], "app_identity_unreadable", "{reply}");
    assert!(
        reply["remedy"]
            .as_str()
            .is_some_and(|remedy| remedy.contains("this platform reads no code-signing identity")),
        "{reply}"
    );
    assert!(carrier.questions().is_empty(), "the person was asked");
    assert!(
        driver.0.lock().unwrap().is_empty(),
        "a keystroke was posted"
    );
}

/// A resolver whose answer can be swapped while a call waits for the person,
/// with each process's signature looked up by pid.
struct SwappingResolver {
    current: Mutex<ProcessGrant>,
    codes: Vec<(u32, InjectedCode)>,
}

impl SwappingResolver {
    fn swap_to(&self, process: ProcessGrant) {
        *self.current.lock().unwrap() = process;
    }
}

impl TargetResolver for SwappingResolver {
    fn resolve(&self, _bundle_identity: &str) -> TargetResolution {
        TargetResolution::Resolved(self.current.lock().unwrap().clone())
    }

    fn app_code(&self, grant: &ProcessGrant) -> Arc<dyn cerebellum::computer_grants::AppCode> {
        let code = self
            .codes
            .iter()
            .find(|(pid, _)| *pid == grant.pid)
            .map(|(_, code)| code.clone())
            .expect("every fixture process has a signature");
        Arc::new(code)
    }
}

/// Process A, resolved before the question, and process B, a different pid
/// answering to the same bundle identity once the person has answered.
fn swapped_processes() -> (ProcessGrant, ProcessGrant) {
    let first = grant();
    let second = ProcessGrant {
        pid: first.pid + 1000,
        process_generation_evidence: format!("{}-later", first.process_generation_evidence),
        ..first.clone()
    };
    (first, second)
}

fn swapping_management(
    first: &ProcessGrant,
    second: &ProcessGrant,
    second_identity: AppIdentity,
) -> (Arc<ManagementPlane>, Arc<SwappingResolver>) {
    let resolver = Arc::new(SwappingResolver {
        current: Mutex::new(first.clone()),
        codes: vec![
            (first.pid, InjectedCode::default()),
            (second.pid, InjectedCode::new(Ok(second_identity))),
        ],
    });
    let management = Arc::new(ManagementPlane::with_computer_grants(
        Arc::clone(&resolver) as Arc<dyn TargetResolver>,
        Arc::new(ComputerGrants::in_memory()),
    ));
    (management, resolver)
}

/// The person answers about process A; by the time the call resumes, process
/// B, signed by someone else, answers to the same bundle identity. B does not
/// act under the answer: the call is refused with `grant_not_recorded`,
/// nothing is posted, and the grant made for A still holds for A.
#[tokio::test]
async fn a_differently_signed_process_swapped_in_during_the_wait_does_not_act() {
    let driver = CountingDriver::default();
    let plane = plane(&driver);
    let (first, second) = swapped_processes();
    let (management, resolver) = swapping_management(&first, &second, team_identity("IMPOSTOR01"));
    let carrier = ScriptedCarrier::default();
    let conversation = caller("conversation-1", false);

    let answering = {
        let carrier = carrier.clone();
        let resolver = Arc::clone(&resolver);
        async move {
            until(|| carrier.questions().len() == 1).await;
            resolver.swap_to(second.clone());
            assert!(carrier.answer_next(answer("allow_30m")));
        }
    };
    let (reply, ()) = tokio::join!(
        serve(
            &plane,
            "computer.type",
            type_request(),
            &management,
            asking(&carrier, conversation.clone()),
        ),
        answering
    );
    assert_eq!(reply["outcome"], "consent_unavailable", "{reply}");
    assert_eq!(reply["reason"], "grant_not_recorded", "{reply}");
    assert!(
        driver.0.lock().unwrap().is_empty(),
        "the swapped-in process was posted to"
    );
    assert!(
        management
            .computer_grants()
            .holds(&conversation, &need_for(&InjectedCode::default())),
        "the grant made for the first process was lost"
    );
    assert_eq!(carrier.questions().len(), 1);
}

/// When the process swapped in during the wait carries the same signature
/// the person approved (the application restarted), it is admitted under
/// the answer and nobody is asked again.
#[tokio::test]
async fn a_same_signed_process_swapped_in_during_the_wait_is_admitted() {
    let (first, second) = swapped_processes();
    let (management, resolver) = swapping_management(&first, &second, team_identity(FIXTURE_TEAM));
    let carrier = ScriptedCarrier::default();

    let answering = {
        let carrier = carrier.clone();
        let resolver = Arc::clone(&resolver);
        let second = second.clone();
        async move {
            until(|| carrier.questions().len() == 1).await;
            resolver.swap_to(second);
            assert!(carrier.answer_next(answer("allow_30m")));
        }
    };
    let consent = asking(&carrier, caller("conversation-1", false));
    let cancel = cerebellum::CancelHandle::pending();
    let (admitted, ()) = tokio::join!(management.admit_app(APP, &consent, &cancel), answering);
    let (process, admission) = admitted.map_err(|refusal| refusal.reply(APP)).unwrap();
    assert!(admission.waited);
    assert_eq!(
        process, second,
        "the call did not act on the process answering now"
    );
    assert_eq!(
        carrier.questions().len(),
        1,
        "the same signature was asked again"
    );
}

fn signed_agent_management(
    code: &InjectedCode,
    storage: &InMemoryAgentGrantStorage,
) -> Arc<ManagementPlane> {
    Arc::new(ManagementPlane::with_computer_grants(
        Arc::new(FixedWithCode(
            TargetResolution::Resolved(grant()),
            code.clone(),
        )),
        Arc::new(agent_grants_over(Arc::new(storage.clone()))),
    ))
}
