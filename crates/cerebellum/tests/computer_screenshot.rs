//! Serving `computer.screenshot` over the wire.
//!
//! The interesting properties here are about ORDER and about what happens when
//! a step fails, neither of which an assertion on the returned outcome can see.

use std::sync::Arc;

use cerebellum::computer_capability::{servable, ComputerPlane, ServeContext};
use cerebellum::management::{ManagementPlane, TargetResolver};
use cerebellum_computer::audit::{ComputerAudit, ComputerCapability};
use cerebellum_computer::capture::{
    BackendError, CaptureBackend, EnumeratedWindow, InMemoryCaptureBackend, WindowFrame,
};
use cerebellum_computer::capture_custody::{
    CaptureCustody, CaptureGrant, CaptureScope, CustodyBounds, InMemoryCustodyStorage,
    InMemoryGrantAuthority,
};
use cerebellum_computer::platform::{ProcessGrant, TargetResolution};
use cerebellum_core::clock::FakeClock;
use cerebellum_core::identity::SessionKind;
use cerebellum_core::journal::{
    EffectClass, InMemoryJournalStorage, IsolationClass, JournalConfig, JournalIdentity,
    ObservabilityClass, Redactor, SeverityInputs, SeverityRecord, ValidatedSeverityTaxonomy,
};
use serde_json::{json, Value};

#[derive(Clone)]
struct TestRedactor;

impl Redactor for TestRedactor {
    fn available(&self) -> bool {
        true
    }

    fn redact(
        &self,
        input: &str,
        _max_bytes: usize,
    ) -> Result<String, cerebellum_core::journal::RedactionUnavailable> {
        Ok(input.replace("secret", "[REDACTED]"))
    }
}

fn taxonomy() -> ValidatedSeverityTaxonomy {
    let effects = [
        EffectClass::Read,
        EffectClass::Mutate,
        EffectClass::Authorize,
    ];
    let isolations = [
        IsolationClass::ResourceScoped,
        IsolationClass::OwnerScoped,
        IsolationClass::Uncontained,
    ];
    let observations = [
        ObservabilityClass::HumanObserved,
        ObservabilityClass::HumanUnobserved,
    ];
    ValidatedSeverityTaxonomy::new(
        "computer-test-v1",
        effects.into_iter().flat_map(move |effect| {
            let isolations = isolations;
            let observations = observations;
            isolations.into_iter().flat_map(move |isolation| {
                let observations = observations;
                observations.into_iter().map(move |observation| {
                    (
                        SeverityInputs {
                            effect_class: effect,
                            isolation_class: isolation,
                            observability_class: observation,
                        },
                        SeverityRecord {
                            tier: if effect == EffectClass::Read { 1 } else { 2 },
                            credential: false,
                            financial: effect == EffectClass::Authorize,
                        },
                    )
                })
            })
        }),
    )
    .unwrap()
}

fn identity() -> JournalIdentity {
    JournalIdentity {
        principal: "prefrontal".into(),
        conversation_key: "conversation-1".into(),
        agent_project_id: "project-1".into(),
        session_kind: SessionKind::Primary,
    }
}

fn bounds() -> CustodyBounds {
    CustodyBounds {
        maximum_verification_duration_ms: 100,
        maximum_pin_lifetime_ms: 50,
        maximum_concurrently_pinned_artifacts: 4,
        maximum_total_pinned_artifact_bytes: 10_000,
        maximum_custody_attachment_bytes: 2_000,
    }
}

fn audit() -> ComputerAudit<TestRedactor, ValidatedSeverityTaxonomy, InMemoryJournalStorage> {
    let mut authority = InMemoryGrantAuthority::default();
    authority.insert(CaptureGrant::new(
        "grant-1",
        CaptureScope::PerWindow,
        0,
        1_000,
    ));
    let custody = CaptureCustody::new(bounds(), authority, InMemoryCustodyStorage::new()).unwrap();
    ComputerAudit::new(
        TestRedactor,
        taxonomy(),
        JournalConfig {
            journal_retention_bytes: 20_000,
            journal_max_entry_bytes: 4_000,
        },
        InMemoryJournalStorage::new(),
        custody,
    )
    .unwrap()
}

/// A resolver that answers from a fixture instead of the window server.
struct Fixed(TargetResolution);

impl TargetResolver for Fixed {
    fn resolve(&self, _bundle_identity: &str) -> TargetResolution {
        self.0.clone()
    }
}

/// A backend that refuses every capture, to prove what survives a failure.
#[derive(Default)]
struct RefusingBackend {
    windows: Vec<EnumeratedWindow>,
}

impl CaptureBackend for RefusingBackend {
    fn screen_recording_liveness(&self) -> cerebellum_computer::platform::PermissionLiveness {
        cerebellum_computer::platform::PermissionLiveness::Live
    }
    fn enumerate_windows(
        &mut self,
        _target: &ProcessGrant,
    ) -> Result<Vec<EnumeratedWindow>, BackendError> {
        Ok(self.windows.clone())
    }
    fn poll_window_change(
        &mut self,
        _target: &ProcessGrant,
    ) -> Result<Option<cerebellum_computer::capture::WindowChange>, BackendError> {
        Ok(None)
    }
    fn capture_window(
        &mut self,
        _request: &cerebellum_computer::capture::WindowCaptureRequest,
    ) -> Result<cerebellum_computer::capture::WindowCaptureFrame, BackendError> {
        Err(BackendError::Capture("the window server refused".into()))
    }
    fn capture_display(
        &mut self,
        _request: &cerebellum_computer::capture::BroadDisplayCaptureRequest,
    ) -> Result<cerebellum_computer::capture::CaptureArtifact, BackendError> {
        Err(BackendError::Capture("not served".into()))
    }
    fn begin_teardown(
        &mut self,
    ) -> Result<cerebellum_computer::capture::BackendTeardownProgress, BackendError> {
        Ok(cerebellum_computer::capture::BackendTeardownProgress::Complete)
    }
    fn poll_teardown(
        &mut self,
        _elapsed_ms: u64,
    ) -> Result<cerebellum_computer::capture::BackendTeardownProgress, BackendError> {
        Ok(cerebellum_computer::capture::BackendTeardownProgress::Complete)
    }
}

fn grant() -> ProcessGrant {
    ProcessGrant {
        pid: 4242,
        bundle_identity: "com.apple.Safari".to_string(),
        process_generation_evidence: "1700000000000000".to_string(),
    }
}

fn management() -> Arc<ManagementPlane> {
    Arc::new(ManagementPlane::new(Arc::new(Fixed(
        TargetResolution::Resolved(grant()),
    ))))
}

fn request() -> Value {
    json!({ "scope": "target_windows", "include_cursor": false })
}

/// Only the two capabilities with no input path are servable.
///
/// Listed by name rather than matched by a wildcard, so a capability added to
/// the vocabulary does not become servable by default. Every actuating
/// capability must be absent until an input path exists: advertising one tells a
/// caller it has a facility that does not exist, and it finds out by using it.
#[test]
fn only_the_observing_capabilities_are_servable() {
    assert_eq!(
        servable("computer.screenshot").map(|s| s.capability()),
        Some(ComputerCapability::Screenshot)
    );
    assert_eq!(
        servable("computer.wait").map(|s| s.capability()),
        Some(ComputerCapability::Wait)
    );

    for actuating in [
        "computer.click",
        "computer.type",
        "computer.keys",
        "computer.scroll",
        "computer.move",
        "computer.drag",
    ] {
        assert!(
            servable(actuating).is_none(),
            "{actuating} has no input path and must not be servable"
        );
    }
    assert!(servable("computer.not-a-capability").is_none());
}

/// Without a lease, a screenshot is refused and names how to get one.
///
/// The refusal is the whole gate: no pixels are read and no journal entry is
/// created, so nothing has to be undone. Asserted by its exact outcome rather
/// than by failure, because a request rejected for a malformed field would also
/// "fail" and would prove nothing about authority.
#[tokio::test]
async fn a_screenshot_without_a_lease_is_refused_with_the_recipe() {
    let plane: ComputerPlane<InMemoryCaptureBackend, _, _, _> = ComputerPlane::new(audit());
    let clock = FakeClock::new();

    let reply = plane
        .serve(
            servable("computer.screenshot").expect("screenshot is servable"),
            &request(),
            ServeContext {
                grantee: "pj-example",
                identity: identity(),
                management: &management(),
                clock: &clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await;

    assert_eq!(reply["outcome"], "no_lease");
    let remedy = reply["remedy"]
        .as_str()
        .expect("a refusal states its remedy");
    assert!(remedy.contains("computer.open_target"), "{remedy}");
}

/// Whole-display capture is refused for want of a broad grant.
///
/// Refused before any lease is consulted or any pixel read: the scope names a
/// blast radius this conversation does not hold, and attempting it first would
/// mean deciding on pixels already taken.
#[tokio::test]
async fn whole_display_capture_is_refused() {
    let plane: ComputerPlane<InMemoryCaptureBackend, _, _, _> = ComputerPlane::new(audit());
    let clock = FakeClock::new();

    let reply = plane
        .serve(
            servable("computer.screenshot").expect("screenshot is servable"),
            &json!({ "scope": "display", "include_cursor": false }),
            ServeContext {
                grantee: "pj-example",
                identity: identity(),
                management: &management(),
                clock: &clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await;

    assert_eq!(reply["outcome"], "broad_grant_required");
}

/// A request asking for the cursor is refused rather than quietly served without it.
///
/// The request schema pins this field to false, so a caller setting it is asking
/// for something the action does not offer. Ignoring it would return a picture
/// that differs from the one requested, with nothing saying so.
#[tokio::test]
async fn asking_for_the_cursor_is_an_invalid_request() {
    let plane: ComputerPlane<InMemoryCaptureBackend, _, _, _> = ComputerPlane::new(audit());
    let clock = FakeClock::new();

    let reply = plane
        .serve(
            servable("computer.screenshot").expect("screenshot is servable"),
            &json!({ "scope": "target_windows", "include_cursor": true }),
            ServeContext {
                grantee: "pj-example",
                identity: identity(),
                management: &management(),
                clock: &clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await;

    assert_eq!(reply["outcome"], "invalid_request");
    assert_eq!(reply["field"], "include_cursor");
}

/// Waiting needs no lease, because it touches nothing.
#[tokio::test]
async fn waiting_needs_no_lease() {
    let plane: ComputerPlane<InMemoryCaptureBackend, _, _, _> = ComputerPlane::new(audit());
    let clock = FakeClock::new();

    let reply = plane
        .serve(
            servable("computer.wait").expect("wait is servable"),
            &json!({ "duration_ms": 250 }),
            ServeContext {
                grantee: "pj-example",
                identity: identity(),
                management: &management(),
                clock: &clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await;

    assert_eq!(reply["outcome"], "completed");
    assert_eq!(reply["waited_ms"], 250);
}

/// A capture that fails still leaves an audit record behind.
///
/// The journal must reserve the action BEFORE any pixel is read, so an action
/// that went wrong is still accounted for. If capture ran first, a failing
/// capture would return the same refusal to the caller while leaving NOTHING
/// recorded — indistinguishable from outside, and an unrecorded observation is
/// what the journal exists to prevent.
///
/// Proved by making capture fail and asserting the journal grew. Asserting the
/// returned outcome alone would pass whichever order the code used.
#[tokio::test]
async fn a_failed_capture_is_still_recorded() {
    let plane: ComputerPlane<RefusingBackend, _, _, _> = ComputerPlane::new(audit());
    let clock = FakeClock::new();
    let before = plane.journal_entry_count().await;

    let reply = plane
        .serve(
            servable("computer.screenshot").expect("screenshot is servable"),
            &request(),
            ServeContext {
                grantee: "pj-example",
                identity: identity(),
                management: &leased_management(&clock).await,
                clock: &clock,
                now_ms: 10,
            },
            |_| RefusingBackend {
                windows: vec![EnumeratedWindow {
                    window_id: "window-1".to_string(),
                    owner_identity: grant(),
                    owner_identity_verified: true,
                    frame: WindowFrame {
                        x: 0,
                        y: 0,
                        width: 800,
                        height: 600,
                    },
                    accessibility_root: None,
                }],
            },
        )
        .await;

    assert_eq!(reply["outcome"], "capture_failed");
    assert!(
        plane.journal_entry_count().await > before,
        "a capture that failed left no record, so the journal was reserved after the pixels \
         rather than before them"
    );
}

/// A management plane holding a live observing lease for the fixture target.
async fn leased_management(clock: &FakeClock) -> Arc<ManagementPlane> {
    let management = management();
    let (reply, _question) = management
        .open_target(
            "pj-example",
            "com.apple.Safari",
            cerebellum_core::consent::ActionKind::Observe,
            true,
            clock,
        )
        .await;
    let ask_id = reply["ask_id"]
        .as_str()
        .expect("an ask is minted")
        .to_string();
    management
        .settle(
            &ask_id,
            Some(&json!({"decision": "allow_10_minutes"})),
            clock,
        )
        .await;
    management
}
