//! A locked screen, refused by name.
//!
//! macOS hides every application's interface from the accessibility API while
//! the screen is locked, though the windows stay listed. Unchecked, a state
//! read returns an empty tree that looks like an empty application, an element
//! lookup finds nothing, and keystrokes land nowhere anyone can confirm. These
//! tests inject the lock state through the platform driver and drive
//! `ComputerPlane::serve` in withholding mode, so every reply shown here also
//! passed its row's result schema.

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cerebellum::computer_capability::{
    servable, ComputerPlane, ResultSchemaEnforcement, ServeContext,
};
use cerebellum::computer_grants::{AppCode, ConsentContext, GrantNeed};
use cerebellum::elicit::AskOutcome;
use cerebellum::management::{ManagementPlane, TargetResolver};
use cerebellum_computer::app_state::image::ImageMapping;
use cerebellum_computer::app_state::session::RegisteredImage;
use cerebellum_computer::app_state::source::{AppStateSource, ReadBounds};
use cerebellum_computer::capture::InMemoryCaptureBackend;
use cerebellum_computer::platform::{
    AccessibilityTreeRequest, AccessibilityTreeResult, AttendancePreconditionRequest,
    AttendancePreconditionResult, CapabilityAdvertisementContext, CapabilityDeclaration,
    DispatchResult, DriverError, EffectObservationRequest, EffectObservationResult, EffectStatus,
    ElementResolutionRequest, ElementResolutionResult, FocusQueryRequest, FocusQueryResult,
    FrontingSnapshot, GlobalDispatchRequest, InputObservationRequest, InputObservationResult,
    InputObserverLiveness, PlatformDriver, ProcessGrant, SemanticDispatchRequest,
    SyntheticDispatchRequest, TargetResolution,
};
use cerebellum_core::clock::FakeClock;
use cerebellum_core::journal::{InMemoryJournalStorage, ValidatedSeverityTaxonomy};
use serde_json::{json, Value};
use support::computer::{
    audit, caller, focused_text_desk, grant, identity, relayed, Desk, InjectedCode,
    ScriptedCarrier, TestRedactor, GRANTEE, TARGET_BUNDLE_ID,
};

/// What the platform reports about the screen, shared by every driver the
/// plane builds so a test can lock the screen between two reads of it.
#[derive(Clone)]
struct LockState(Arc<Mutex<Option<bool>>>);

impl LockState {
    fn new(state: Option<bool>) -> Self {
        Self(Arc::new(Mutex::new(state)))
    }

    fn set(&self, state: Option<bool>) {
        *self.0.lock().unwrap() = state;
    }
}

/// A driver reporting the injected lock state and recording every dispatch
/// it is asked for, semantic, per-process or global. Any recorded dispatch
/// means something was posted.
#[derive(Clone)]
struct LockDriver {
    lock: LockState,
    posted: Arc<Mutex<Vec<&'static str>>>,
}

impl PlatformDriver for LockDriver {
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
        self.posted.lock().unwrap().push("semantic");
        Err(DriverError::Unsupported(
            "test dispatches nothing semantically",
        ))
    }
    fn dispatch_per_pid(
        &mut self,
        _request: SyntheticDispatchRequest,
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<DispatchResult, DriverError> {
        self.posted.lock().unwrap().push("per_pid");
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
        _request: GlobalDispatchRequest,
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<DispatchResult, DriverError> {
        self.posted.lock().unwrap().push("global");
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
    fn session_locked(&self) -> Option<bool> {
        *self.lock.0.lock().unwrap()
    }
}

/// A resolver that counts how often an application name was resolved, so a
/// test can show a refused call never got as far as resolving its target.
#[derive(Clone, Default)]
struct CountingResolver(Arc<AtomicUsize>);

impl TargetResolver for CountingResolver {
    fn resolve(&self, _bundle_identity: &str) -> TargetResolution {
        self.0.fetch_add(1, Ordering::SeqCst);
        TargetResolution::Resolved(grant())
    }

    fn app_code(&self, _grant: &ProcessGrant) -> Arc<dyn AppCode> {
        Arc::new(InjectedCode::default())
    }
}

type Plane = ComputerPlane<
    InMemoryCaptureBackend,
    TestRedactor,
    ValidatedSeverityTaxonomy,
    InMemoryJournalStorage,
    LockDriver,
>;

struct Rig {
    lock: LockState,
    posted: Arc<Mutex<Vec<&'static str>>>,
    resolves: Arc<AtomicUsize>,
    desk: Desk,
    plane: Plane,
    management: Arc<ManagementPlane>,
}

/// The fixture application frontmost with a plain text field focused, no
/// grant held, and the screen in `lock`.
fn rig(lock: Option<bool>) -> Rig {
    let lock = LockState::new(lock);
    let posted = Arc::new(Mutex::new(Vec::new()));
    let desk = focused_text_desk();
    let driver = LockDriver {
        lock: lock.clone(),
        posted: Arc::clone(&posted),
    };
    let plane = ComputerPlane::with_synthetic_driver_and_result_schema_enforcement(
        audit(),
        ResultSchemaEnforcement::Withhold,
        move || driver.clone(),
    )
    .with_app_state_source(desk.source())
    // Admitted so a keystroke into a background target reaches the fronting
    // question; no test here fronts anything unless it asks for that.
    .with_fronting_bracket_admitted(true);
    let resolver = CountingResolver::default();
    let resolves = Arc::clone(&resolver.0);
    Rig {
        lock,
        posted,
        resolves,
        desk,
        plane,
        management: Arc::new(ManagementPlane::new(Arc::new(resolver))),
    }
}

async fn serve(rig: &Rig, name: &str, arguments: &Value, consent: ConsentContext) -> Value {
    let clock = FakeClock::new();
    let reply = rig
        .plane
        .serve(
            servable(name).expect("the row is served"),
            arguments,
            ServeContext {
                cancel: cerebellum::CancelHandle::pending(),
                grantee: GRANTEE,
                identity: identity(),
                management: &rig.management,
                consent,
                clock: &clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await
        .unwrap_or_else(|error| panic!("{name} replied outside its row: {error:?}"));
    assert!(
        rig.plane.result_schema_findings().is_empty(),
        "{name}: {:?}",
        rig.plane.result_schema_findings()
    );
    reply
}

/// One well-formed request for every served row.
fn every_row() -> Vec<(&'static str, Value)> {
    let point = json!({"x": 1, "y": 1});
    vec![
        ("computer.read_state", json!({"target": TARGET_BUNDLE_ID})),
        ("computer.press_element", json!({"element_id": "e1"})),
        (
            "computer.press_point",
            json!({"image_id": "i1", "x": 1, "y": 1}),
        ),
        (
            "computer.write_text",
            json!({"element_id": "e1", "text": "hi", "write_mode": "replace_value"}),
        ),
        (
            "computer.type",
            json!({"target": TARGET_BUNDLE_ID, "text": "hi"}),
        ),
        (
            "computer.keys",
            json!({"target": TARGET_BUNDLE_ID, "keys": ["s"]}),
        ),
        (
            "computer.takeover_move",
            json!({"image_id": "i1", "to": point}),
        ),
        (
            "computer.takeover_drag",
            json!({"image_id": "i1", "from": point, "to": point}),
        ),
        (
            "computer.takeover_scroll",
            json!({"target": TARGET_BUNDLE_ID, "axis": "vertical", "amount_lines": 1}),
        ),
        (
            "computer.wait",
            json!({
                "app": TARGET_BUNDLE_ID,
                "predicate": {"kind": "element_present", "element": {"Identifier": "ready"}},
                "timeout_ms": 0,
            }),
        ),
    ]
}

fn assert_screen_locked(name: &str, reply: &Value) {
    assert_eq!(reply["outcome"], "screen_locked", "{name}: {reply}");
    assert_eq!(reply["reason"], "screen_locked", "{name}: {reply}");
    let remedy = reply["remedy"].as_str().unwrap_or_default();
    assert!(
        remedy.contains("unlocked") && remedy.contains("browser_use"),
        "{name}: the remedy names neither way on: {reply}"
    );
    assert!(
        reply.get("screen_lock_state").is_none(),
        "{name}: a known lock state is not disclosed as unknown: {reply}"
    );
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

/// A locked screen refuses every row by name, and the refusal comes first:
/// no application is resolved, nobody is asked, no element is read, pressed,
/// written or hit-tested, nothing is posted and nothing is journaled.
///
/// The carrier would answer every question with an allow, so a call that did
/// reach the consent step would be admitted and show up here as a question
/// and a resolution rather than hang.
#[tokio::test]
async fn a_locked_screen_refuses_every_row_before_resolving_asking_or_posting() {
    let rig = rig(Some(true));
    let carrier = ScriptedCarrier::answering(&["allow_conversation"; 20]);
    let journal_before = rig.plane.journal_entry_count().await;

    for (name, arguments) in every_row() {
        let reply = serve(&rig, name, &arguments, relayed(&carrier)).await;
        assert_screen_locked(name, &reply);
    }

    assert!(
        carrier.questions().is_empty(),
        "a locked call asked the person"
    );
    assert_eq!(
        rig.resolves.load(Ordering::SeqCst),
        0,
        "a locked call resolved its application"
    );
    assert!(
        rig.posted.lock().unwrap().is_empty(),
        "a locked call posted"
    );
    {
        let desk = rig.desk.state();
        assert!(desk.presses.is_empty(), "a locked call pressed");
        assert!(desk.writes.is_empty(), "a locked call wrote");
        assert!(desk.hit_scopes.is_empty(), "a locked call hit-tested");
        assert_eq!(desk.focus_reads, 0, "a locked call read focus");
    }
    assert_eq!(
        rig.plane.journal_entry_count().await,
        journal_before,
        "a locked call was journaled as an action"
    );
}

/// The screen locks while the call waits for the person's answer: the answer
/// is kept, the call refuses `screen_locked` without acting, and once the
/// screen is unlocked the retry goes through on the grant just made, with no
/// second question.
#[tokio::test]
async fn a_lock_during_the_consent_wait_refuses_after_the_answer_and_the_grant_survives() {
    for name in ["computer.type", "computer.read_state", "computer.wait"] {
        let rig = rig(Some(false));
        let carrier = ScriptedCarrier::default();
        let arguments = every_row()
            .into_iter()
            .find(|(row, _)| *row == name)
            .unwrap()
            .1;

        let answering = {
            let carrier = carrier.clone();
            let lock = rig.lock.clone();
            async move {
                until(|| carrier.questions().len() == 1).await;
                lock.set(Some(true));
                assert!(carrier.answer_next(AskOutcome::Answered(
                    json!({"decision": "allow_conversation"})
                )));
            }
        };
        let (reply, ()) = tokio::join!(serve(&rig, name, &arguments, relayed(&carrier)), answering);
        assert_screen_locked(name, &reply);
        assert!(rig.posted.lock().unwrap().is_empty(), "{name} posted");
        assert_eq!(rig.desk.state().focus_reads, 0, "{name} read focus");

        let need = GrantNeed::App {
            bundle_identity: TARGET_BUNDLE_ID.to_string(),
            display_name: TARGET_BUNDLE_ID.to_string(),
            code: Arc::new(InjectedCode::default()),
        };
        assert!(
            rig.management.computer_grants().holds(&caller(), &need),
            "{name}: the answer given during the wait was lost"
        );

        if name == "computer.type" {
            rig.lock.set(Some(false));
            let retried = serve(&rig, name, &arguments, relayed(&carrier)).await;
            assert_eq!(retried["outcome"], "delivery_unconfirmed", "{retried}");
            assert_eq!(*rig.posted.lock().unwrap(), ["per_pid"]);
            assert_eq!(carrier.questions().len(), 1, "the retry asked again");
        }
    }
}

/// Lock the screen once the pending question appears, then answer it allow.
async fn lock_then_allow(carrier: &ScriptedCarrier, lock: &LockState, question: usize) {
    until(|| carrier.questions().len() == question).await;
    lock.set(Some(true));
    assert!(carrier.answer_next(AskOutcome::Answered(
        json!({"decision": "allow_conversation"})
    )));
}

/// The element- and point-addressed rows ask for their application's grant
/// on the session's own process, and are re-checked after that wait too:
/// nothing is pressed, written or hit-tested once the screen locked.
#[tokio::test]
async fn a_lock_during_the_wait_of_an_element_or_point_action_refuses_before_acting() {
    for name in [
        "computer.press_element",
        "computer.write_text",
        "computer.press_point",
    ] {
        let rig = rig(Some(false));
        let conversation = identity().conversation_key;
        let sessions = rig.management.app_state_sessions();
        // A read recorded straight into the session, so its ids and image
        // exist without the read having asked for (and held) the grant.
        let raw = rig
            .desk
            .read_app_state(&grant(), ReadBounds::default())
            .expect("the desk reads");
        let read = sessions.observe(&conversation, &grant(), &raw);
        let field = read.roots[0].children[0]
            .element_id
            .clone()
            .expect("the text field is numbered");
        let image_id = sessions.register_image(
            &conversation,
            RegisteredImage {
                bundle_identity: TARGET_BUNDLE_ID.to_string(),
                pid: grant().pid,
                process_generation: grant().process_generation_evidence,
                width_px: 100,
                height_px: 100,
                mapping: ImageMapping::for_window(
                    (0.0, 0.0),
                    (100.0, 100.0),
                    (100, 100),
                    (100, 100),
                )
                .expect("a whole-window mapping"),
            },
        );
        rig.desk.state().application_hit = Some((2, Some(grant().pid)));
        let arguments = match name {
            "computer.press_element" => json!({"element_id": field}),
            "computer.write_text" => {
                json!({"element_id": field, "text": "hi", "write_mode": "replace_value"})
            }
            _ => json!({"image_id": image_id, "x": 5, "y": 5}),
        };

        let carrier = ScriptedCarrier::default();
        let (reply, ()) = tokio::join!(
            serve(&rig, name, &arguments, relayed(&carrier)),
            lock_then_allow(&carrier, &rig.lock, 1)
        );
        assert_screen_locked(name, &reply);
        let desk = rig.desk.state();
        assert!(desk.presses.is_empty(), "{name} pressed");
        assert!(desk.writes.is_empty(), "{name} wrote");
        assert!(desk.hit_scopes.is_empty(), "{name} hit-tested");
        assert!(rig.posted.lock().unwrap().is_empty(), "{name} posted");
    }
}

/// Shortcut delivery requires a takeover already held by the conversation.
/// A grant answered while the screen locks does not authorize posting through
/// the lock when the next shortcut arrives.
#[tokio::test]
async fn a_lock_after_takeover_is_granted_refuses_background_chords_before_posting() {
    let rig = rig(Some(false));
    support::computer::grant_app(&rig.management).await;
    rig.desk.state().frontmost = Some(grant().pid + 1);
    let carrier = ScriptedCarrier::default();
    let consent = relayed(&carrier);
    let cancel = cerebellum::CancelHandle::pending();
    let (admitted, ()) = tokio::join!(
        rig.management
            .computer_grants()
            .require(&GrantNeed::Takeover, &consent, &cancel),
        lock_then_allow(&carrier, &rig.lock, 1)
    );
    admitted.unwrap();
    let reply = serve(
        &rig,
        "computer.keys",
        &json!({"target": TARGET_BUNDLE_ID, "keys": ["command", "a"]}),
        relayed(&carrier),
    )
    .await;
    assert_screen_locked("computer.keys", &reply);
    assert_eq!(carrier.questions().len(), 1);
    assert!(rig.posted.lock().unwrap().is_empty(), "the shortcut posted");
}

/// The takeover grant's wait is re-checked the same way: a pointer row whose
/// question was answered after the screen locked posts nothing.
#[tokio::test]
async fn a_lock_during_the_takeover_wait_refuses_before_placing_or_posting() {
    let rig = rig(Some(false));
    let carrier = ScriptedCarrier::default();
    let arguments = json!({"target": TARGET_BUNDLE_ID, "axis": "vertical", "amount_lines": 1});
    let answering = {
        let carrier = carrier.clone();
        let lock = rig.lock.clone();
        async move {
            until(|| carrier.questions().len() == 1).await;
            lock.set(Some(true));
            assert!(carrier.answer_next(AskOutcome::Answered(
                json!({"decision": "allow_conversation"})
            )));
        }
    };
    let (reply, ()) = tokio::join!(
        serve(
            &rig,
            "computer.takeover_scroll",
            &arguments,
            relayed(&carrier)
        ),
        answering
    );
    assert_screen_locked("computer.takeover_scroll", &reply);
    assert!(rig.posted.lock().unwrap().is_empty(), "the scroll posted");
    assert_eq!(
        carrier.questions()[0]["params"]["target"]["kind"],
        "machine",
        "the question answered was the takeover grant's"
    );
}

/// A lock state that cannot be read does not stop the call, but the reply
/// says so, because a blind read looks exactly like an empty application.
/// A state read as unlocked carries no such disclosure.
#[tokio::test]
async fn an_unreadable_lock_state_proceeds_and_is_disclosed() {
    let carrier = ScriptedCarrier::answering(&["allow_conversation"; 4]);
    for (state, disclosed) in [(None, true), (Some(false), false)] {
        let rig = rig(state);
        let read = serve(
            &rig,
            "computer.read_state",
            &json!({"target": TARGET_BUNDLE_ID}),
            relayed(&carrier),
        )
        .await;
        assert_eq!(read["outcome"], "completed", "{read}");
        let typed = serve(
            &rig,
            "computer.type",
            &json!({"target": TARGET_BUNDLE_ID, "text": "hi"}),
            relayed(&carrier),
        )
        .await;
        assert_eq!(typed["outcome"], "delivery_unconfirmed", "{typed}");
        assert_eq!(*rig.posted.lock().unwrap(), ["per_pid"]);

        for reply in [&read, &typed] {
            if disclosed {
                assert_eq!(reply["screen_lock_state"], "unknown", "{reply}");
            } else {
                assert!(reply.get("screen_lock_state").is_none(), "{reply}");
            }
        }
    }
}
