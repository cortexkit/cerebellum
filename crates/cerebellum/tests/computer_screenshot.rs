//! Serving `computer.screenshot` over the wire.
//!
//! The interesting properties here are about ORDER and about what happens when
//! a step fails, neither of which an assertion on the returned outcome can see.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use cerebellum::computer_capability::{
    servable, ComputerPlane, ComputerPlaneUnavailable, ServeContext,
};
use cerebellum::management::{ManagementPlane, TargetResolver};
use cerebellum_computer::audit::{ComputerAudit, ComputerCapability};
use cerebellum_computer::capture::{
    BackendError, CaptureArtifact, CaptureBackend, EnumeratedWindow, InMemoryCaptureBackend,
    WindowFrame,
};
use cerebellum_computer::capture_custody::{
    CaptureCustody, CaptureGrant, CaptureScope, CustodyBounds, InMemoryCustodyStorage,
    InMemoryGrantAuthority,
};
use cerebellum_computer::platform::{ProcessGrant, TargetResolution};
use cerebellum_core::clock::FakeClock;
use cerebellum_core::identity::SessionKind;
use cerebellum_core::journal::{
    DurableState, EffectClass, InMemoryJournalStorage, IoDiagnostic, IsolationClass, JournalConfig,
    JournalIdentity, JournalStorage, ObservabilityClass, Redactor, SeverityInputs, SeverityRecord,
    StorageError, ValidatedSeverityTaxonomy,
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

fn custody() -> CaptureCustody {
    let mut authority = InMemoryGrantAuthority::default();
    authority.insert(CaptureGrant::new(
        "grant-1",
        CaptureScope::PerWindow,
        0,
        1_000,
    ));
    CaptureCustody::new(bounds(), authority, InMemoryCustodyStorage::new()).unwrap()
}

fn audit() -> ComputerAudit<TestRedactor, ValidatedSeverityTaxonomy, InMemoryJournalStorage> {
    ComputerAudit::new(
        TestRedactor,
        taxonomy(),
        JournalConfig {
            journal_retention_bytes: 20_000,
            journal_max_entry_bytes: 4_000,
        },
        InMemoryJournalStorage::new(),
        custody(),
    )
    .unwrap()
}

#[derive(Clone, Debug)]
struct FailAfterInitialization {
    saves: Arc<AtomicUsize>,
}

impl JournalStorage for FailAfterInitialization {
    fn load(&self) -> Result<DurableState, StorageError> {
        Ok(DurableState::default())
    }

    fn save(&self, _state: &DurableState) -> Result<(), StorageError> {
        if self.saves.fetch_add(1, Ordering::SeqCst) == 0 {
            Ok(())
        } else {
            Err(StorageError::TemporaryWrite {
                path: PathBuf::from("/unwritable/journal.tmp"),
                source: IoDiagnostic {
                    kind: std::io::ErrorKind::PermissionDenied,
                    message: "permission denied".to_string(),
                },
            })
        }
    }
}

/// A resolver that answers from a fixture instead of the window server.
struct Fixed(TargetResolution);

impl TargetResolver for Fixed {
    fn resolve(&self, _bundle_identity: &str) -> TargetResolution {
        self.0.clone()
    }
}

/// A backend that captures successfully, to prove what a real capture produces.
///
/// Its counterpart refuses everything, and a suite holding only that one cannot
/// reach the code that builds a result from pixels: every test ends at the
/// failure branch. That gap let an artifact built with no bytes and zero
/// dimensions ship, which custody refused on the first real capture.
struct CapturingBackend {
    windows: Vec<EnumeratedWindow>,
    png: Vec<u8>,
}

impl CaptureBackend for CapturingBackend {
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
        request: &cerebellum_computer::capture::WindowCaptureRequest,
    ) -> Result<cerebellum_computer::capture::WindowCaptureFrame, BackendError> {
        let window = self
            .windows
            .iter()
            .find(|window| window.window_id == request.filter.window_id)
            .ok_or_else(|| BackendError::Capture("no such window".into()))?;
        let (frame, bytes) = match request.region {
            Some(region) => {
                let expected = (window.frame.width as usize)
                    .checked_mul(window.frame.height as usize)
                    .and_then(|pixels| pixels.checked_mul(4));
                let bytes = if expected == Some(self.png.len()) {
                    let stride = window.frame.width as usize * 4;
                    let row_bytes = region.width_px as usize * 4;
                    let mut cropped = Vec::with_capacity(row_bytes * region.height_px as usize);
                    for row in 0..region.height_px as usize {
                        let start =
                            (region.y_px as usize + row) * stride + region.x_px as usize * 4;
                        cropped.extend_from_slice(&self.png[start..start + row_bytes]);
                    }
                    cropped
                } else {
                    vec![0; region.width_px as usize * region.height_px as usize * 4]
                };
                (
                    WindowFrame {
                        x: window.frame.x + region.x_px as i32,
                        y: window.frame.y + region.y_px as i32,
                        width: region.width_px,
                        height: region.height_px,
                    },
                    bytes,
                )
            }
            None => (window.frame, self.png.clone()),
        };
        Ok(cerebellum_computer::capture::WindowCaptureFrame {
            owner_identity: window.owner_identity.clone(),
            owner_identity_verified: true,
            frame,
            captured_at_ms: request.captured_at_ms,
            artifact: CaptureArtifact::Bytes(bytes),
            accessibility_root: None,
        })
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

#[test]
fn journal_boot_failure_message_names_its_path_and_typed_cause() {
    let path = PathBuf::from("/unwritable/cortexkit/cerebellum/journal/computer.json");
    let reason = ComputerPlaneUnavailable::JournalStorage {
        path: path.clone(),
        error: StorageError::CreateDirectory {
            path: path.parent().expect("journal directory").to_path_buf(),
            source: IoDiagnostic {
                kind: std::io::ErrorKind::PermissionDenied,
                message: "permission denied".to_string(),
            },
        },
    };

    let message = reason.to_string();

    assert!(message.contains(path.to_str().expect("UTF-8 fixture path")));
    assert!(message.contains("CreateDirectory"));
    assert!(message.contains("PermissionDenied"));
}

/// The reviewed semantic click path joins the two observing handlers.
///
/// Listed by name rather than matched by a wildcard, so the five unreviewed
/// actuating capabilities cannot become servable by default.
#[test]
fn only_reviewed_or_observing_capabilities_are_servable() {
    assert_eq!(
        servable("computer.click").map(|s| s.capability()),
        Some(ComputerCapability::Click)
    );
    assert_eq!(
        servable("computer.screenshot").map(|s| s.capability()),
        Some(ComputerCapability::Screenshot)
    );
    assert_eq!(
        servable("computer.wait").map(|s| s.capability()),
        Some(ComputerCapability::Wait)
    );

    for actuating in [
        "computer.type",
        "computer.keys",
        "computer.scroll",
        "computer.move",
        "computer.drag",
    ] {
        assert!(
            servable(actuating).is_none(),
            "{actuating} has no reviewed wire path and must not be servable"
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

/// A runtime journal write failure refuses before the capture backend is built.
#[tokio::test]
async fn runtime_journal_save_failure_prevents_capture() {
    let clock = FakeClock::new();
    let storage = FailAfterInitialization {
        saves: Arc::new(AtomicUsize::new(0)),
    };
    let audit = ComputerAudit::new(
        TestRedactor,
        taxonomy(),
        JournalConfig {
            journal_retention_bytes: 20_000,
            journal_max_entry_bytes: 4_000,
        },
        storage,
        custody(),
    )
    .expect("initial journal state is writable");
    let plane: ComputerPlane<InMemoryCaptureBackend, _, _, _> = ComputerPlane::new(audit);
    let backend_built = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&backend_built);

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
            move |_| {
                observed.store(true, Ordering::SeqCst);
                InMemoryCaptureBackend::default()
            },
        )
        .await;

    assert_eq!(reply["outcome"], "audit_unavailable");
    assert_eq!(reply["detail"], "Journal(StorageUnavailable)");
    assert!(!backend_built.load(Ordering::SeqCst));
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

/// A successful capture is retained, and the retained artifact describes it.
///
/// The artifact handed to custody carries the encoded bytes and the dimensions
/// they describe. An artifact built with no bytes and zero dimensions passes
/// every check in this handler and is refused by custody at the moment of
/// retention, which returns a capture the caller never receives -- so the
/// assertion is on the RESULT reaching the caller, not merely on custody
/// having been called.
#[tokio::test]
async fn a_successful_capture_is_retained_and_returned() {
    let clock = FakeClock::new();
    let plane = ComputerPlane::new(audit());
    let png = vec![0x89, b'P', b'N', b'G', 1, 2, 3, 4, 5, 6, 7, 8];

    let reply = plane
        .serve(
            servable("computer.screenshot").expect("screenshot is servable"),
            &json!({ "scope": "target_windows", "include_cursor": false }),
            ServeContext {
                grantee: "pj-example",
                identity: identity(),
                management: &leased_management(&clock).await,
                clock: &clock,
                now_ms: 10,
            },
            |_| CapturingBackend {
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
                png: png.clone(),
            },
        )
        .await;

    assert_eq!(
        reply["outcome"], "captured",
        "capture was not retained: {reply}"
    );

    let windows = reply["windows"].as_array().expect("windows are returned");
    assert_eq!(windows.len(), 1);
    assert_eq!(windows[0]["width_px"], 800);
    assert_eq!(windows[0]["height_px"], 600);
    assert!(
        !windows[0]["image_png_b64"]
            .as_str()
            .expect("an encoded image")
            .is_empty(),
        "the reply carried no image"
    );
}

fn patterned_bgra(width: u32, height: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(width as usize * height as usize * 4);
    for y in 0..height {
        for x in 0..width {
            bytes.extend_from_slice(&[(x % 256) as u8, (y % 256) as u8, 0, 255]);
        }
    }
    bytes
}

fn decode_base64(encoded: &str) -> Vec<u8> {
    const TABLE: [i8; 256] = {
        let mut table = [-1i8; 256];
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0;
        while i < alphabet.len() {
            table[alphabet[i] as usize] = i as i8;
            i += 1;
        }
        table
    };
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;
    for byte in encoded.bytes() {
        if byte == b'=' {
            break;
        }
        let value = TABLE[byte as usize];
        assert!(value >= 0, "invalid base64");
        buf = (buf << 6) | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    out
}

/// A region request captures that rectangle of the window, not the whole window.
///
/// Asserted on the returned pixel dimensions (the decoded buffer size), not on
/// the echoed region: an echo can agree with the request while the image is
/// still the whole window.
#[tokio::test]
async fn a_region_request_captures_the_region_and_echoes_it() {
    let clock = FakeClock::new();
    let plane = ComputerPlane::new(audit());
    let png = patterned_bgra(80, 60);

    let reply = plane
        .serve(
            servable("computer.screenshot").expect("screenshot is servable"),
            &json!({
                "scope": "target_windows",
                "include_cursor": false,
                "region": { "x_px": 10, "y_px": 20, "width_px": 30, "height_px": 16 }
            }),
            ServeContext {
                grantee: "pj-example",
                identity: identity(),
                management: &leased_management(&clock).await,
                clock: &clock,
                now_ms: 10,
            },
            |_| CapturingBackend {
                windows: vec![EnumeratedWindow {
                    window_id: "window-1".to_string(),
                    owner_identity: grant(),
                    owner_identity_verified: true,
                    frame: WindowFrame {
                        x: 0,
                        y: 0,
                        width: 80,
                        height: 60,
                    },
                    accessibility_root: None,
                }],
                png: png.clone(),
            },
        )
        .await;

    assert_eq!(
        reply["outcome"], "captured",
        "region capture failed: {reply}"
    );
    assert_eq!(
        reply["region"],
        json!({ "x_px": 10, "y_px": 20, "width_px": 30, "height_px": 16 })
    );
    let windows = reply["windows"].as_array().expect("windows are returned");
    assert_eq!(windows.len(), 1);
    assert_eq!(windows[0]["width_px"], 30);
    assert_eq!(windows[0]["height_px"], 16);
    assert_eq!(
        windows[0]["region"],
        json!({ "x_px": 10, "y_px": 20, "width_px": 30, "height_px": 16 })
    );

    let captured = decode_base64(windows[0]["image_png_b64"].as_str().expect("image"));
    assert_eq!(captured.len(), 30 * 16 * 4, "the image was not cropped");
    assert_eq!(
        &captured[0..4],
        &[10, 20, 0, 255],
        "the crop started at the wrong pixel"
    );
    assert_ne!(captured, png, "the reply still carried the whole window");
}

/// A backend that captures the whole window despite a region on the request.
///
/// The serving handler must refuse that rather than relabel the full window as
/// the requested region.
struct IgnoringRegionBackend {
    windows: Vec<EnumeratedWindow>,
    png: Vec<u8>,
}

impl CaptureBackend for IgnoringRegionBackend {
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
        request: &cerebellum_computer::capture::WindowCaptureRequest,
    ) -> Result<cerebellum_computer::capture::WindowCaptureFrame, BackendError> {
        let window = self
            .windows
            .iter()
            .find(|window| window.window_id == request.filter.window_id)
            .ok_or_else(|| BackendError::Capture("no such window".into()))?;
        Ok(cerebellum_computer::capture::WindowCaptureFrame {
            owner_identity: window.owner_identity.clone(),
            owner_identity_verified: true,
            frame: window.frame,
            captured_at_ms: request.captured_at_ms,
            artifact: CaptureArtifact::Bytes(self.png.clone()),
            accessibility_root: None,
        })
    }
    fn capture_display(
        &mut self,
        _request: &cerebellum_computer::capture::BroadDisplayCaptureRequest,
    ) -> Result<CaptureArtifact, BackendError> {
        Err(BackendError::Capture(
            "display capture is not served".into(),
        ))
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

#[tokio::test]
async fn a_full_window_capture_is_refused_when_a_region_was_requested() {
    let clock = FakeClock::new();
    let plane = ComputerPlane::new(audit());
    let reply = plane
        .serve(
            servable("computer.screenshot").expect("screenshot is servable"),
            &json!({
                "scope": "target_windows",
                "include_cursor": false,
                "region": { "x_px": 10, "y_px": 20, "width_px": 30, "height_px": 16 }
            }),
            ServeContext {
                grantee: "pj-example",
                identity: identity(),
                management: &leased_management(&clock).await,
                clock: &clock,
                now_ms: 10,
            },
            |_| IgnoringRegionBackend {
                windows: vec![EnumeratedWindow {
                    window_id: "window-1".to_string(),
                    owner_identity: grant(),
                    owner_identity_verified: true,
                    frame: WindowFrame {
                        x: 0,
                        y: 0,
                        width: 80,
                        height: 60,
                    },
                    accessibility_root: None,
                }],
                png: patterned_bgra(80, 60),
            },
        )
        .await;

    assert_eq!(reply["outcome"], "invalid_request");
    assert_eq!(reply["field"], "region");
    assert_eq!(reply["reason"], "region_not_honoured");
}

/// A target whose windows carry no pixels is reported as such.
///
/// Distinct from a capture that failed: there was nothing to capture rather
/// than an attempt that went wrong, and the remedies differ -- open a window,
/// versus retry or check permissions.
#[tokio::test]
async fn a_target_with_no_capturable_window_says_so() {
    let clock = FakeClock::new();
    let plane = ComputerPlane::new(audit());

    let reply = plane
        .serve(
            servable("computer.screenshot").expect("screenshot is servable"),
            &json!({ "scope": "target_windows", "include_cursor": false }),
            ServeContext {
                grantee: "pj-example",
                identity: identity(),
                management: &leased_management(&clock).await,
                clock: &clock,
                now_ms: 10,
            },
            |_| CapturingBackend {
                windows: Vec::new(),
                png: Vec::new(),
            },
        )
        .await;

    assert_eq!(
        reply["outcome"], "no_window_captured",
        "unexpected: {reply}"
    );
    assert!(
        reply["remedy"]
            .as_str()
            .is_some_and(|remedy| !remedy.is_empty()),
        "the refusal named no way forward"
    );
}

/// An unreadable window list is never reported as the application being absent.
///
/// The two answers send a person in opposite directions: `not_running` says to
/// start the application, while an unreadable list says nothing about whether it
/// is running at all.
///
/// Not hypothetical. Under concurrent load on a real machine the permission
/// query reported capture as permitted while enumeration failed in the same
/// instant with a declined-permission error, so a transient window-server
/// failure arrives wearing a denial's clothes. Reporting that as "not running"
/// tells someone to start a second copy of an application already in front of
/// them, and the second copy then makes the target ambiguous.
#[tokio::test]
async fn an_unreadable_window_list_is_not_reported_as_the_application_being_absent() {
    let plane = Arc::new(ManagementPlane::new(Arc::new(Fixed(
        TargetResolution::Unreadable,
    ))));
    let clock = FakeClock::new();

    let (body, question) = plane
        .open_target(
            "agent-under-test",
            "com.example.App",
            cerebellum_core::consent::ActionKind::Observe,
            true,
            &clock,
        )
        .await;

    assert_eq!(
        body["outcome"], "targets_unreadable",
        "an unreadable window list produced: {body}"
    );
    assert!(
        question.is_none(),
        "a person was asked to approve a target nothing could see: {body}"
    );
}
