//! App and takeover grants, and the consent a computer call waits for.
//!
//! Driven through `ComputerPlane::serve` -- the boundary the wire route calls
//! -- and through the management plane's grant admission, with the person's
//! answers scripted. Journals and grant stores are held in memory throughout.

mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use cerebellum::computer_capability::{servable, ComputerPlane, ServeContext};
use cerebellum::computer_grants::{
    AlwaysGrantRecord, ComputerGrants, ConsentContext, ConsentRefusal, FilesystemGrantStorage,
    GrantCaller, GrantNeed, GrantStorage, GrantStoreError, GrantStoreState, InMemoryGrantStorage,
    QuestionCarrier, GRANT_STORE_VERSION,
};
use cerebellum::elicit::AskOutcome;
use cerebellum::management::ManagementPlane;
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
use support::computer::{audit, grant, identity, Fixed, ScriptedCarrier, TestRedactor, GRANTEE};

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
        .with_app_state_source(support::computer::focused_text_desk().source())
}

fn caller(conversation: &str, attested: bool) -> GrantCaller {
    GrantCaller {
        conversation_key: conversation.to_string(),
        agent_project_id: GRANTEE.to_string(),
        durable_identity_attested: attested,
    }
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
    question["params"]["requestedSchema"]["properties"]["decision"]["enum"]
        .as_array()
        .expect("the question offers its decisions")
        .iter()
        .map(|decision| decision.as_str().unwrap().to_string())
        .collect()
}

fn answer(decision: &str) -> AskOutcome {
    AskOutcome::Answered(json!({"decision": decision}))
}

async fn until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
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
    }
}

/// One question per application per conversation, and an answer inside the
/// wait returns the call's real result with no second call.
///
/// The person answers five seconds in. The same call then posts its
/// keystrokes and returns their result. Typing again, pressing keys and
/// waiting in the same application raise no second question; the same
/// application in another conversation gets its own.
#[tokio::test]
async fn one_question_per_app_per_conversation_and_an_answer_returns_the_real_result() {
    let driver = CountingDriver::default();
    let plane = plane(&driver);
    let management = in_memory_management();
    let carrier = ScriptedCarrier::default();

    let answering = {
        let carrier = carrier.clone();
        async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            assert!(carrier.answer_next(answer("allow_conversation")));
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
    assert_eq!(params["grant_kind"], "app");
    // No running name can be read in a test, so the bundle identity is shown.
    assert_eq!(params["app"], APP);
    assert_eq!(decisions(&questions[0]), ["allow_conversation", "deny"]);

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

    carrier.queue(answer("allow_conversation"));
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
        2,
        "another conversation was admitted by this conversation's grant"
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

    assert!(carrier.answer_next(answer("allow_conversation")));
    let grants = Arc::clone(management.computer_grants());
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

/// An "always" answer is written to the store and honoured by a module that
/// reopens it: a new conversation of the same attested agent is not asked.
#[tokio::test]
async fn an_always_answer_survives_a_module_restart() {
    let storage = InMemoryGrantStorage::new();
    let first = management_over(ComputerGrants::open(
        Arc::new(storage.clone()),
        Some(MACHINE.to_string()),
    ));
    let carrier = ScriptedCarrier::answering(&["allow_always"]);
    let admission = admit(&first, &carrier, caller("conversation-1", true))
        .await
        .expect("the always answer admits the call");
    assert_eq!(admission.persisted, Some(Ok(())));
    let mut reply = json!({"outcome": "completed"});
    admission.decorate(&mut reply);
    assert_eq!(reply["grant_persisted"], true);

    let stored = storage.load().unwrap();
    assert_eq!(stored.version, GRANT_STORE_VERSION);
    assert_eq!(stored.records.len(), 1);
    assert_eq!(stored.records[0].machine_uuid, MACHINE);
    assert_eq!(stored.records[0].agent_project_id, GRANTEE);

    // A second plane over the same storage is the module after a restart.
    let restarted = management_over(ComputerGrants::open(
        Arc::new(storage.clone()),
        Some(MACHINE.to_string()),
    ));
    let silent = ScriptedCarrier::default();
    admit(&restarted, &silent, caller("conversation-9", true))
        .await
        .expect("the stored always grant admits a new conversation");
    assert!(
        silent.questions().is_empty(),
        "the restarted module asked again"
    );
}

/// A record naming another machine grants nothing here, and the listing
/// reports it apart. A backup restored onto a different machine therefore
/// cannot carry the person's trust across.
#[tokio::test]
async fn a_record_naming_another_machine_grants_nothing() {
    let storage = InMemoryGrantStorage::new();
    storage
        .save(&GrantStoreState {
            version: GRANT_STORE_VERSION,
            records: vec![AlwaysGrantRecord {
                agent_project_id: GRANTEE.to_string(),
                bundle_identity: APP.to_string(),
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
    assert_eq!(listing["other_machine_grants"][0]["bundle_identity"], APP);
}

/// "Always" is offered only to a bind whose agent and session kind the daemon
/// attested; an unattested bind cannot store or use a durable grant.
#[tokio::test]
async fn an_unattested_bind_is_not_offered_always() {
    let storage = InMemoryGrantStorage::new();
    let management = management_over(ComputerGrants::open(
        Arc::new(storage.clone()),
        Some(MACHINE.to_string()),
    ));

    let unattested = ScriptedCarrier::answering(&["allow_always"]);
    let refused = admit(&management, &unattested, caller("conversation-1", false)).await;
    assert_eq!(
        decisions(&unattested.questions()[0]),
        ["allow_conversation", "deny"],
        "an unattested bind was offered always"
    );
    // An answer the question did not offer is consent to nothing.
    assert_eq!(refused.unwrap_err()["reason"], "unrecognized_answer");
    assert!(storage.load().unwrap().records.is_empty());

    let attested = ScriptedCarrier::answering(&["deny"]);
    let _ = admit(&management, &attested, caller("conversation-2", true)).await;
    assert_eq!(
        decisions(&attested.questions()[0]),
        ["allow_conversation", "allow_always", "deny"]
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

/// A store that cannot be read withholds every "always" grant, says so, and is
/// never written over: not by a later answer, not by a revoke.
#[tokio::test]
async fn a_corrupt_store_fails_closed_and_is_disclosed() {
    let directory = scratch_directory("corrupt-grants");
    let path = directory.join("computer_grants.json");
    std::fs::write(&path, b"{ not json").unwrap();
    let grants = ComputerGrants::open(
        Arc::new(FilesystemGrantStorage::new(&path)),
        Some(MACHINE.to_string()),
    );
    assert!(matches!(
        grants.store_error(),
        Some(GrantStoreError::Corrupt { .. })
    ));
    let listing = grants.list();
    assert_eq!(listing["store"]["state"], "unreadable");
    assert_eq!(listing["store"]["reason"], "grant_store_corrupt");
    assert_eq!(
        grants.revoke(GRANTEE, APP, false)["outcome"],
        "store_unavailable"
    );

    let management = management_over(grants);
    let carrier = ScriptedCarrier::answering(&["allow_conversation"]);
    admit(&management, &carrier, caller("conversation-1", true))
        .await
        .expect("a conversation answer still admits");
    assert_eq!(
        decisions(&carrier.questions()[0]),
        ["allow_conversation", "deny"],
        "always was offered over a store that could not be read"
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"{ not json");

    // A version this build does not read is withheld the same way.
    std::fs::write(&path, br#"{"version": 2, "records": []}"#).unwrap();
    let newer = ComputerGrants::open(
        Arc::new(FilesystemGrantStorage::new(&path)),
        Some(MACHINE.to_string()),
    );
    assert_eq!(
        newer.store_error(),
        Some(GrantStoreError::UnknownVersion { found: 2 })
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// Storage whose writes always fail.
struct UnwritableStorage;

impl GrantStorage for UnwritableStorage {
    fn load(&self) -> Result<GrantStoreState, GrantStoreError> {
        Ok(GrantStoreState::default())
    }
    fn save(&self, _state: &GrantStoreState) -> Result<(), GrantStoreError> {
        Err(GrantStoreError::WriteFailed {
            detail: "read-only file system".to_string(),
        })
    }
}

/// When an "always" answer cannot be written, the person's yes still holds for
/// this conversation and the call proceeds, and the reply says the answer was
/// not stored and why.
#[tokio::test]
async fn a_failed_always_write_grants_the_conversation_and_says_so() {
    let driver = CountingDriver::default();
    let plane = plane(&driver);
    let management = management_over(ComputerGrants::open(
        Arc::new(UnwritableStorage),
        Some(MACHINE.to_string()),
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
    assert_eq!(reply["outcome"], "delivery_unconfirmed", "{reply}");
    assert_eq!(reply["grant_persisted"], false, "{reply}");
    assert_eq!(reply["reason"], "grant_store_write_failed", "{reply}");
    assert_eq!(driver.0.lock().unwrap().len(), 1);

    let again = serve(
        &plane,
        "computer.type",
        type_request(),
        &management,
        asking(&carrier, caller("conversation-1", true)),
    )
    .await;
    assert_eq!(again["outcome"], "delivery_unconfirmed", "{again}");
    assert!(again.get("grant_persisted").is_none(), "{again}");
    assert_eq!(carrier.questions().len(), 1);
    assert_eq!(management.computer_grants().list()["grants"], json!([]));
}

/// Storage whose writes take long enough that a call released early would be
/// seen acting before the write finished.
#[derive(Clone, Default)]
struct SlowStorage(InMemoryGrantStorage);

impl GrantStorage for SlowStorage {
    fn load(&self) -> Result<GrantStoreState, GrantStoreError> {
        self.0.load()
    }
    fn save(&self, state: &GrantStoreState) -> Result<(), GrantStoreError> {
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
    let management = management_over(ComputerGrants::open(
        Arc::new(storage.clone()),
        Some(MACHINE.to_string()),
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
    assert_eq!(reply["outcome"], "delivery_unconfirmed", "{reply}");
    assert_eq!(reply["grant_persisted"], true, "{reply}");
    assert_eq!(
        storage.0.load().unwrap().records.len(),
        1,
        "the call acted before its always answer was stored"
    );
}

/// The takeover grant is asked separately, never offers "always", and is not
/// satisfied by any app grant.
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
    let carrier = ScriptedCarrier::answering(&["allow_conversation", "allow_conversation"]);
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
    assert_eq!(takeover["params"]["grant_kind"], "takeover");
    assert_eq!(decisions(takeover), ["allow_conversation", "deny"]);
    assert!(takeover["params"].get("app").is_none());
    // Pinned byte for byte: the host shows this line unchanged, and it has to
    // cover both uses of the grant, fronting an application for keystrokes
    // and driving the real pointer.
    assert_eq!(
        takeover["params"]["message"],
        "Takeover lets the agent bring apps to the front, type into them, and move your real \
         mouse pointer. It is machine-wide for this conversation and can reach every \
         application on the screen."
    );
    assert!(grants.holds(&attested, &GrantNeed::Takeover));
    assert!(!grants.holds(&caller("conversation-2", true), &GrantNeed::Takeover));
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

/// Two calls needing the same grant at once raise one question between them.
/// The answer runs the first; the second is told the grant is held.
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
            // Give the second call time to join before the answer lands.
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(carrier.answer_next(answer("allow_conversation")));
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
    assert_eq!(
        outcomes,
        ["consent_granted_not_executed", "delivery_unconfirmed"]
    );
    assert_eq!(
        driver.0.lock().unwrap().len(),
        1,
        "one answer ran two calls"
    );
}

/// Revoking a durable grant removes the record, and the next call asks again.
/// A dry run changes nothing.
#[tokio::test]
async fn a_revoked_always_grant_is_asked_for_again() {
    let storage = InMemoryGrantStorage::new();
    let management = management_over(ComputerGrants::open(
        Arc::new(storage.clone()),
        Some(MACHINE.to_string()),
    ));
    let carrier = ScriptedCarrier::answering(&["allow_always", "deny"]);
    admit(&management, &carrier, caller("conversation-1", true))
        .await
        .expect("the always answer admits");

    let grants = management.computer_grants();
    assert_eq!(grants.revoke(GRANTEE, APP, true)["outcome"], "would_revoke");
    assert_eq!(storage.load().unwrap().records.len(), 1);
    assert_eq!(grants.revoke(GRANTEE, APP, false)["outcome"], "revoked");
    assert!(storage.load().unwrap().records.is_empty());
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
    carrier.queue(AskOutcome::NotPutToAnyone);
    carrier.queue(AskOutcome::NoAnswer);

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
        "Nobody could be asked; retry when the person is available."
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
