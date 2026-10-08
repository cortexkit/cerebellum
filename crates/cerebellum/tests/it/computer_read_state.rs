//! `computer.read_state` served through the plane: the tree, its ids across
//! conversations, and the window image, each checked against the row's
//! result schema in withholding mode, so a reply the vocabulary does not
//! declare fails here rather than reaching a caller.

use super::support;

use std::sync::{Arc, Mutex};

use cerebellum::computer_capability::{
    servable, ComputerPlane, ResultSchemaEnforcement, ServeContext,
};
use cerebellum::computer_grants::{ConsentContext, GrantCaller, QuestionCarrier};
use cerebellum::management::ManagementPlane;
use cerebellum_computer::app_state::source::{
    AppStateReadError, AppStateSource, ElementValue, RawAppState, RawElement, ReadBounds,
};
use cerebellum_computer::capture::{EnumeratedWindow, InMemoryCaptureBackend, WindowFrame};
use cerebellum_computer::platform::{PermissionLiveness, ProcessGrant};
use cerebellum_core::clock::FakeClock;
use cerebellum_core::journal::{JournalIdentity, JournalStorage};
use serde_json::{json, Value};
use support::computer::{
    audit, grant, granted_management, identity, no_relay, ScriptedCarrier, GRANTEE,
    TARGET_BUNDLE_ID,
};

/// A reader that answers with a fixture tree, or with a scripted failure.
struct FixtureSource(Mutex<Result<RawAppState, AppStateReadError>>);

impl FixtureSource {
    fn new(roots: Vec<RawElement>) -> Arc<Self> {
        Arc::new(Self(Mutex::new(Ok(RawAppState {
            roots,
            focused: None,
            unreadable_subtrees: 0,
            read_bound_reached: false,
        }))))
    }

    fn replace(&self, roots: Vec<RawElement>) {
        *self.0.lock().unwrap() = Ok(RawAppState {
            roots,
            focused: None,
            unreadable_subtrees: 0,
            read_bound_reached: false,
        });
    }
}

impl AppStateSource for FixtureSource {
    fn read_app_state(
        &self,
        _target: &ProcessGrant,
        _bounds: ReadBounds,
    ) -> Result<RawAppState, AppStateReadError> {
        self.0.lock().unwrap().clone()
    }
}

/// A chat window with a composer, and a password sheet attached to it.
fn chat_window() -> RawElement {
    let mut composer = RawElement::fixture(3, "AXTextArea");
    composer.description = Some("Message @IceTea".into());
    composer.value_settable = true;
    let mut path = RawElement::fixture(6, "AXTextField").titled("PathTextField");
    path.value_settable = true;
    let mut secret = RawElement::fixture(7, "AXTextField").titled("Password");
    secret.subrole = Some("AXSecureTextField".into());
    secret.value_description = Some("SECRET_SENTINEL".into());
    secret.value = ElementValue::Text("SECRET_SENTINEL".into());
    let sheet = RawElement::fixture(5, "AXSheet")
        .titled("GoToWindow")
        .with_children(vec![path, secret]);
    RawElement::fixture(1, "AXWindow")
        .titled("Discord")
        .with_children(vec![
            RawElement::fixture(2, "AXGroup").with_children(vec![composer]),
            sheet,
        ])
}

type Plane<S = cerebellum_core::journal::InMemoryJournalStorage> = ComputerPlane<
    InMemoryCaptureBackend,
    support::computer::TestRedactor,
    cerebellum_core::journal::ValidatedSeverityTaxonomy,
    S,
>;

fn plane(source: Arc<FixtureSource>) -> Plane {
    ComputerPlane::with_result_schema_enforcement(audit(), ResultSchemaEnforcement::Withhold)
        .with_permission_liveness(super::support::computer::live_permissions())
        .with_app_state_source(source)
        .with_image_freshness_source(Arc::new(FixtureFreshness {
            repaints: false,
            before:
                cerebellum::computer_capability::image_freshness::WindowVisibility::FullyVisible,
            after: cerebellum::computer_capability::image_freshness::WindowVisibility::FullyVisible,
            seen: Mutex::new(vec![]),
        }))
}

fn identity_for(conversation_key: &str) -> JournalIdentity {
    JournalIdentity {
        conversation_key: conversation_key.into(),
        ..identity()
    }
}

/// A consent context for `conversation_key` whose one question is answered
/// "allow for this conversation".
fn allowing(conversation_key: &str) -> ConsentContext {
    let (drain_sender, drain) = tokio::sync::watch::channel(false);
    std::mem::forget(drain_sender);
    ConsentContext::new(
        GrantCaller {
            conversation_key: conversation_key.into(),
            agent_project_id: GRANTEE.into(),
            durable_identity_attested: false,
        },
        Some(
            Arc::new(ScriptedCarrier::answering(&["allow_conversation"]))
                as Arc<dyn QuestionCarrier>,
        ),
        Arc::new(cerebellum::computer_grants::AlwaysOpenRoute),
        drain,
        None,
    )
}

async fn serve<S: JournalStorage + Send + 'static>(
    plane: &Plane<S>,
    management: &Arc<ManagementPlane>,
    conversation_key: &str,
    consent: ConsentContext,
    arguments: Value,
    backend: InMemoryCaptureBackend,
) -> Value {
    let clock = FakeClock::new();
    plane
        .serve(
            servable("computer.read_state").expect("read_state is served"),
            &arguments,
            ServeContext {
                cancel: cerebellum::CancelHandle::for_uninterruptible_probe(),
                grantee: GRANTEE,
                identity: identity_for(conversation_key),
                management,
                consent,
                clock: &clock,
                now_ms: 10,
            },
            move |_| backend,
        )
        .await
        .expect("every read_state reply conforms to its row")
}

/// The element ids of a rendered state: the first word of every line after
/// the header line, where that word is a run tag (two lowercase letters)
/// followed by a number.
fn ids(tree: &str) -> Vec<String> {
    tree.lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().next())
        .filter(|word| {
            word.len() > 2
                && word.as_bytes()[..2].iter().all(u8::is_ascii_lowercase)
                && word.as_bytes()[2..].iter().all(u8::is_ascii_digit)
        })
        .map(str::to_string)
        .collect()
}

fn line_with<'a>(tree: &'a str, needle: &str) -> &'a str {
    tree.lines()
        .find(|line| line.contains(needle))
        .unwrap_or_else(|| panic!("no line with {needle} in\n{tree}"))
}

/// The tree comes back through `serve` under a held app grant and passes the
/// row's result schema: the sheet sits under its window, the composer is
/// settable, and the secure field's value never appears.
#[tokio::test]
async fn read_state_serves_the_tree_and_passes_withholding() {
    let management = granted_management().await;
    let plane = plane(FixtureSource::new(vec![chat_window()]));
    let reply = serve(
        &plane,
        &management,
        "conversation-1",
        no_relay(),
        json!({"target": TARGET_BUNDLE_ID}),
        InMemoryCaptureBackend::default(),
    )
    .await;

    assert_eq!(reply["outcome"], "completed", "{reply}");
    let tree = reply["state_text"].as_str().unwrap();
    assert!(line_with(tree, "text area").ends_with("text area (settable) Message @IceTea"));
    let sheet = line_with(tree, "sheet GoToWindow");
    assert!(
        sheet.starts_with("  ") && !sheet.starts_with("   "),
        "the sheet is not under its window: {sheet}"
    );
    assert!(line_with(tree, "PathTextField").starts_with("    "));
    assert!(!tree.contains("SECRET_SENTINEL"), "{tree}");
    assert_eq!(reply["unreadable_subtrees"], 0);
    assert!(reply.get("image").is_none() && reply.get("image_unavailable").is_none());
    assert!(plane.result_schema_findings().is_empty());
}

/// Filters narrow the reply and keep the ancestor path; a zoom id this
/// session does not hold is refused as stale.
#[tokio::test]
async fn filters_and_a_stale_zoom_id_are_served_through_withholding() {
    let management = granted_management().await;
    let plane = plane(FixtureSource::new(vec![chat_window()]));
    let reply = serve(
        &plane,
        &management,
        "conversation-1",
        no_relay(),
        json!({"target": TARGET_BUNDLE_ID, "role_filter": ["text field"], "text_filter": "path"}),
        InMemoryCaptureBackend::default(),
    )
    .await;
    // The header, the window, the sheet that holds the match, and the match.
    let tree = reply["state_text"].as_str().unwrap();
    assert_eq!(tree.lines().count(), 4, "{tree}");

    let stale = serve(
        &plane,
        &management,
        "conversation-1",
        no_relay(),
        json!({"target": TARGET_BUNDLE_ID, "zoom": "999999"}),
        InMemoryCaptureBackend::default(),
    )
    .await;
    assert_eq!(stale["outcome"], "stale_element", "{stale}");

    let invalid = serve(
        &plane,
        &management,
        "conversation-1",
        no_relay(),
        json!({"target": TARGET_BUNDLE_ID, "role_filter": []}),
        InMemoryCaptureBackend::default(),
    )
    .await;
    assert_eq!(invalid["outcome"], "invalid_request");
    assert_eq!(invalid["field"], "role_filter");
}

/// Two conversations reading the same application hold disjoint ids, and a
/// conversation's ids end with it.
#[tokio::test]
async fn two_conversations_hold_disjoint_ids_that_end_with_them() {
    let management = Arc::new(ManagementPlane::new(Arc::new(support::computer::Fixed(
        cerebellum_computer::platform::TargetResolution::Resolved(grant()),
    ))));
    let plane = plane(FixtureSource::new(vec![chat_window()]));
    let first = serve(
        &plane,
        &management,
        "conversation-a",
        allowing("conversation-a"),
        json!({"target": TARGET_BUNDLE_ID}),
        InMemoryCaptureBackend::default(),
    )
    .await;
    let second = serve(
        &plane,
        &management,
        "conversation-b",
        allowing("conversation-b"),
        json!({"target": TARGET_BUNDLE_ID}),
        InMemoryCaptureBackend::default(),
    )
    .await;
    let (first, second) = (
        ids(first["state_text"].as_str().unwrap()),
        ids(second["state_text"].as_str().unwrap()),
    );
    assert!(!first.is_empty());
    assert!(
        first.iter().all(|id| !second.contains(id)),
        "{first:?} {second:?}"
    );

    // conversation-b cannot scope a read by conversation-a's id.
    let foreign = serve(
        &plane,
        &management,
        "conversation-b",
        no_relay_for("conversation-b"),
        json!({"target": TARGET_BUNDLE_ID, "zoom": first[1]}),
        InMemoryCaptureBackend::default(),
    )
    .await;
    assert_eq!(foreign["outcome"], "stale_element", "{foreign}");

    assert_eq!(management.app_state_sessions().session_count(), 2);
    management.end_conversation("conversation-a");
    assert_eq!(management.app_state_sessions().session_count(), 1);
}

fn no_relay_for(conversation_key: &str) -> ConsentContext {
    ConsentContext::without_carrier(GrantCaller {
        conversation_key: conversation_key.into(),
        agent_project_id: GRANTEE.into(),
        durable_identity_attested: false,
    })
}

/// A minimal JPEG: start of image, one frame header, padding, end of image.
pub(super) fn jpeg(width: u16, height: u16, padding: usize) -> Vec<u8> {
    let mut bytes = vec![0xFF, 0xD8];
    bytes.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x0B, 0x08]);
    bytes.extend_from_slice(&height.to_be_bytes());
    bytes.extend_from_slice(&width.to_be_bytes());
    bytes.extend_from_slice(&[0x01, 0x01, 0x11, 0x00]);
    bytes.extend(std::iter::repeat_n(0u8, padding));
    bytes.extend_from_slice(&[0xFF, 0xD9]);
    bytes
}

/// A backend holding one window of the fixture application, at (100, 50)
/// points and 1000 by 600 points, captured at 2000 by 1200 pixels and scaled
/// to the JPEG given.
pub(super) fn capturing(image: Vec<u8>) -> InMemoryCaptureBackend {
    let mut backend = InMemoryCaptureBackend::default();
    backend.set_windows(vec![EnumeratedWindow {
        window_id: "77".into(),
        owner_identity: grant(),
        owner_identity_verified: true,
        frame: WindowFrame {
            x: 100,
            y: 50,
            width: 1000,
            height: 600,
        },
        accessibility_root: None,
    }]);
    backend.set_frontmost_window(Some("77".into()));
    backend.set_vision_frame("77", 2000, 1200, image);
    backend
}

/// The image comes back as JPEG with its size read from its own header, and
/// its id maps a known pixel back to its known desktop point.
#[tokio::test]
async fn the_window_image_is_served_with_its_header_size_and_its_mapping() {
    let management = granted_management().await;
    let plane = plane(FixtureSource::new(vec![chat_window()]));
    let image = jpeg(1250, 750, 64);
    let reply = serve(
        &plane,
        &management,
        "conversation-1",
        no_relay(),
        json!({"target": TARGET_BUNDLE_ID, "include_image": true}),
        capturing(image.clone()),
    )
    .await;

    let served = &reply["image"];
    assert_eq!(served["mime"], "image/jpeg", "{reply}");
    assert_eq!(
        (served["width_px"].clone(), served["height_px"].clone()),
        (json!(1250), json!(750))
    );
    assert_eq!(
        cerebellum_core::serde_base64::decode(served["data_b64"].as_str().unwrap()).unwrap(),
        image
    );
    let registered = management
        .app_state_sessions()
        .resolve_image("conversation-1", served["image_id"].as_str().unwrap())
        .expect("the image is registered to the conversation");
    // Image pixel (625, 125) is captured pixel (1000, 200), window point
    // (500, 100), desktop point (600, 150).
    assert_eq!(
        registered.mapping.pixel_to_desktop(625.0, 125.0),
        (600.0, 150.0)
    );
    assert!(management
        .app_state_sessions()
        .resolve_image("conversation-2", served["image_id"].as_str().unwrap())
        .is_none());
    assert!(plane.result_schema_findings().is_empty());
}

/// A startup denial cannot be bypassed by a capture backend that would now be
/// live. Screen Recording remains optional: return the tree and disclose the
/// missing image, without constructing a backend or asking the OS again.
#[tokio::test]
async fn startup_screen_recording_readings_withhold_only_the_image_until_restart() {
    use cerebellum_computer::platform::{
        PermissionLivenessReport, PermissionProbeResult, PermissionService,
    };
    let management = granted_management().await;
    let clock = FakeClock::new();
    for state in [
        PermissionLiveness::Unavailable,
        PermissionLiveness::GrantedPendingRelaunch,
        PermissionLiveness::Unresolved,
        PermissionLiveness::ProbeFailed,
    ] {
        let report = PermissionLivenessReport::from_results(
            [
                (PermissionService::Accessibility, PermissionLiveness::Live),
                (PermissionService::ScreenRecording, state),
            ]
            .into_iter()
            .map(|(service, liveness)| PermissionProbeResult {
                service,
                liveness,
                responsible_process: "ck-cerebellum".into(),
                off_main: true,
            }),
        );
        let plane = plane(FixtureSource::new(vec![chat_window()])).with_permission_liveness(report);
        let reply = plane
            .serve(
                servable("computer.read_state").unwrap(),
                &json!({"target": TARGET_BUNDLE_ID, "include_image": true}),
                ServeContext {
                    cancel: cerebellum::CancelHandle::for_uninterruptible_probe(),
                    grantee: GRANTEE,
                    identity: identity(),
                    management: &management,
                    consent: no_relay(),
                    clock: &clock,
                    now_ms: 10,
                },
                |_| panic!("a missing startup permission must not construct the capture backend"),
            )
            .await
            .unwrap();
        assert_eq!(reply["outcome"], "completed", "{reply}");
        assert!(reply["state_text"].as_str().unwrap().contains("GoToWindow"));
        assert_eq!(
            reply["image_unavailable"]["reason"], "screen_recording_not_live",
            "{reply}"
        );
        assert!(reply.get("image").is_none(), "{reply}");
    }
}

/// Each way the image can fail at the wire returns the tree, no image, and
/// the declared reason; custody refusing the image releases no bytes.
#[tokio::test]
async fn a_missing_image_is_declared_and_the_tree_still_returns() {
    let management = granted_management().await;
    let plane = plane(FixtureSource::new(vec![chat_window()]));
    let arguments = json!({"target": TARGET_BUNDLE_ID, "include_image": true});

    let mut unlit = capturing(jpeg(1250, 750, 0));
    unlit.set_permission_liveness(PermissionLiveness::Unavailable);
    let mut windowless = capturing(jpeg(1250, 750, 0));
    windowless.set_frontmost_window(None);
    let mut refusing = capturing(jpeg(1250, 750, 0));
    refusing.set_vision_frame("77", 2000, 1200, b"not an image".to_vec());

    for (backend, reason) in [
        (unlit, "screen_recording_not_live"),
        (windowless, "no_window_captured"),
        (refusing, "capture_failed"),
        (
            capturing(jpeg(0, 0, 0)).tap_zero_capture(),
            "image_not_scalable",
        ),
    ] {
        let reply = serve(
            &plane,
            &management,
            "conversation-1",
            no_relay(),
            arguments.clone(),
            backend,
        )
        .await;
        assert_eq!(reply["outcome"], "completed", "{reply}");
        assert!(reply["state_text"].as_str().unwrap().contains("GoToWindow"));
        assert!(reply.get("image").is_none(), "{reason}: {reply}");
        assert_eq!(reply["image_unavailable"]["reason"], reason, "{reply}");
    }
    assert!(plane.result_schema_findings().is_empty());

    // A successful tree also needs a durable row, not just a captured image.
    let failing: Plane<_> = ComputerPlane::with_result_schema_enforcement(
        support::computer::failing_audit(),
        ResultSchemaEnforcement::Withhold,
    )
    .with_permission_liveness(super::support::computer::live_permissions())
    .with_app_state_source(FixtureSource::new(vec![chat_window()]))
    .with_image_freshness_source(Arc::new(FixtureFreshness {
        repaints: false,
        before: cerebellum::computer_capability::image_freshness::WindowVisibility::FullyVisible,
        after: cerebellum::computer_capability::image_freshness::WindowVisibility::FullyVisible,
        seen: Mutex::new(vec![]),
    }));
    let reply = serve(
        &failing,
        &management,
        "conversation-1",
        no_relay(),
        arguments,
        capturing(jpeg(1250, 750, 0)),
    )
    .await;
    assert!(reply.get("image").is_none(), "{reply}");
    assert_eq!(reply["outcome"], "audit_unavailable", "{reply}");
    assert!(reply.get("state_text").is_none(), "{reply}");
}

trait ZeroCapture {
    fn tap_zero_capture(self) -> Self;
}

impl ZeroCapture for InMemoryCaptureBackend {
    /// A capture of a window with no area.
    fn tap_zero_capture(mut self) -> Self {
        self.set_vision_frame("77", 0, 0, Vec::new());
        self
    }
}

/// The application quitting mid-read is reported as not running, and an
/// application that does not answer is a read of nothing with the whole
/// application counted unreadable, never an empty tree presented as complete.
#[tokio::test]
async fn an_unreadable_application_is_disclosed_rather_than_shown_empty() {
    let management = granted_management().await;
    let source = FixtureSource::new(vec![]);
    let plane = plane(source.clone());

    *source.0.lock().unwrap() = Err(AppStateReadError::Unreadable);
    let reply = serve(
        &plane,
        &management,
        "conversation-1",
        no_relay(),
        json!({"target": TARGET_BUNDLE_ID}),
        InMemoryCaptureBackend::default(),
    )
    .await;
    assert_eq!(reply["outcome"], "completed");
    assert_eq!(reply["unreadable_subtrees"], 1);
    assert_eq!(reply["reason"], "application_unreadable");

    let before_refusal = plane.journal_entry_count().await;
    *source.0.lock().unwrap() = Err(AppStateReadError::TargetGone);
    let gone = serve(
        &plane,
        &management,
        "conversation-1",
        no_relay(),
        json!({"target": TARGET_BUNDLE_ID}),
        InMemoryCaptureBackend::default(),
    )
    .await;
    assert_eq!(gone["outcome"], "not_running");
    assert_eq!(gone["bundle_identity"], TARGET_BUNDLE_ID);
    assert_eq!(plane.journal_entry_count().await, before_refusal);

    source.replace(vec![chat_window()]);
    assert!(plane.result_schema_findings().is_empty());
}

/// Without the app grant and with nobody to ask, the read refuses the way
/// every consent-needing row does, and reads nothing.
#[tokio::test]
async fn an_ungranted_read_is_refused_before_anything_is_read() {
    let management = support::computer::management();
    let plane = plane(FixtureSource::new(vec![chat_window()]));
    let before = plane.journal_entry_count().await;
    let reply = serve(
        &plane,
        &management,
        "conversation-1",
        no_relay(),
        json!({"target": TARGET_BUNDLE_ID}),
        InMemoryCaptureBackend::default(),
    )
    .await;
    assert_eq!(reply["outcome"], "consent_unavailable", "{reply}");
    assert!(reply.get("state_text").is_none());
    assert_eq!(management.app_state_sessions().session_count(), 0);
    assert_eq!(plane.journal_entry_count().await, before);
}

struct FixtureFreshness {
    repaints: bool,
    before: cerebellum::computer_capability::image_freshness::WindowVisibility,
    after: cerebellum::computer_capability::image_freshness::WindowVisibility,
    seen: Mutex<Vec<Option<String>>>,
}

impl cerebellum::computer_capability::image_freshness::ImageFreshnessSource for FixtureFreshness {
    fn inspect(
        &self,
        target: &ProcessGrant,
        window_id: Option<&str>,
    ) -> (
        bool,
        cerebellum::computer_capability::image_freshness::WindowVisibility,
    ) {
        assert_eq!(target.bundle_identity, TARGET_BUNDLE_ID);
        self.seen.lock().unwrap().push(window_id.map(str::to_owned));
        (
            self.repaints,
            if window_id.is_some() {
                self.after
            } else {
                self.before
            },
        )
    }
}

#[tokio::test]
async fn covered_unmeasured_app_image_refusal_passes_withholding_and_keeps_tree() {
    use cerebellum::computer_capability::image_freshness::WindowVisibility;
    let management = granted_management().await;
    for visibility in [WindowVisibility::Covered, WindowVisibility::Unknown] {
        let facts = Arc::new(FixtureFreshness {
            repaints: false,
            before: visibility,
            after: visibility,
            seen: Mutex::new(vec![]),
        });
        let plane = plane(FixtureSource::new(vec![chat_window()]))
            .with_image_freshness_source(facts.clone());
        let journal_before = plane.journal_entry_count().await;
        let reply = serve(
            &plane,
            &management,
            "conversation-1",
            no_relay(),
            json!({"target": TARGET_BUNDLE_ID, "include_image": true}),
            capturing(jpeg(1250, 750, 0)),
        )
        .await;
        assert_eq!(reply["outcome"], "completed", "{reply}");
        assert_eq!(
            reply["image_unavailable"],
            json!({"reason": "window_covered_may_be_stale"})
        );
        assert!(reply.get("image").is_none());
        assert!(reply["state_text"].as_str().unwrap().contains("GoToWindow"));
        assert!(plane.result_schema_findings().is_empty());
        assert_eq!(*facts.seen.lock().unwrap(), vec![None]);
        assert_eq!(
            plane.journal_entry_count().await,
            journal_before + 1,
            "the successful tree read is recorded even though its image was withheld"
        );
    }
}

#[tokio::test]
async fn capture_rechecks_exact_window_and_only_visible_unmeasured_images_remain_available() {
    use cerebellum::computer_capability::image_freshness::WindowVisibility::*;
    let management = granted_management().await;
    for (repaints, before, after, allowed) in [
        (false, FullyVisible, FullyVisible, true),
        (false, FullyVisible, Covered, false),
        (false, FullyVisible, Unknown, false),
    ] {
        let facts = Arc::new(FixtureFreshness {
            repaints,
            before,
            after,
            seen: Mutex::new(vec![]),
        });
        let plane = plane(FixtureSource::new(vec![chat_window()]))
            .with_image_freshness_source(facts.clone());
        let reply = serve(
            &plane,
            &management,
            "conversation-1",
            no_relay(),
            json!({"target": TARGET_BUNDLE_ID, "include_image": true}),
            capturing(jpeg(1250, 750, 0)),
        )
        .await;
        assert_eq!(reply["outcome"], "completed");
        assert_eq!(reply.get("image").is_some(), allowed, "{reply}");
        if !allowed {
            assert_eq!(
                reply["image_unavailable"]["reason"],
                "window_covered_may_be_stale"
            );
        }
        assert_eq!(*facts.seen.lock().unwrap(), vec![None, Some("77".into())]);
        assert!(plane.result_schema_findings().is_empty());
    }
}

#[tokio::test]
async fn tree_only_reads_do_not_probe_image_freshness() {
    use cerebellum::computer_capability::image_freshness::WindowVisibility::Covered;
    let facts = Arc::new(FixtureFreshness {
        repaints: false,
        before: Covered,
        after: Covered,
        seen: Mutex::new(vec![]),
    });
    let plane =
        plane(FixtureSource::new(vec![chat_window()])).with_image_freshness_source(facts.clone());
    let management = granted_management().await;
    let reply = serve(
        &plane,
        &management,
        "conversation-1",
        no_relay(),
        json!({"target": TARGET_BUNDLE_ID}),
        InMemoryCaptureBackend::default(),
    )
    .await;
    assert_eq!(reply["outcome"], "completed");
    assert!(facts.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn bring_to_front_is_boolean_and_inert_without_an_image_request() {
    let management = granted_management().await;
    let facts = Arc::new(FixtureFreshness {
        repaints: false,
        before: cerebellum::computer_capability::image_freshness::WindowVisibility::Covered,
        after: cerebellum::computer_capability::image_freshness::WindowVisibility::Covered,
        seen: Mutex::new(vec![]),
    });
    let storage = cerebellum_core::journal::InMemoryJournalStorage::new();
    let plane: Plane = ComputerPlane::with_result_schema_enforcement(
        support::computer::audit_with_storage(storage.clone()),
        ResultSchemaEnforcement::Withhold,
    )
    .with_permission_liveness(support::computer::live_permissions())
    .with_app_state_source(FixtureSource::new(vec![chat_window()]))
    .with_image_freshness_source(facts.clone());
    let invalid = serve(
        &plane,
        &management,
        "conversation-1",
        no_relay(),
        json!({"target": TARGET_BUNDLE_ID, "bring_to_front": "yes"}),
        InMemoryCaptureBackend::default(),
    )
    .await;
    assert_eq!(invalid["outcome"], "invalid_request");
    assert_eq!(invalid["field"], "bring_to_front");
    let tree = serve(
        &plane,
        &management,
        "conversation-1",
        no_relay(),
        json!({"target": TARGET_BUNDLE_ID, "bring_to_front": true}),
        InMemoryCaptureBackend::default(),
    )
    .await;
    assert_eq!(tree["outcome"], "completed");
    assert!(tree.get("image_unavailable").is_none());
    assert!(facts.seen.lock().unwrap().is_empty());
    let row = recorded_read(&storage);
    assert!(row.get("image_decision").is_none());
    assert!(row.get("image_fronting").is_none());
}

pub(super) fn recorded_read(storage: &cerebellum_core::journal::InMemoryJournalStorage) -> Value {
    let state = serde_json::to_value(storage.load().unwrap()).unwrap();
    let entries = state["entries"].as_object().unwrap();
    assert_eq!(
        entries.len(),
        1,
        "one read must have exactly one terminal row"
    );
    let row = entries.values().next().unwrap();
    let bytes = cerebellum_core::serde_base64::decode(row["bytes"].as_str().unwrap()).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

pub(super) fn assert_no_screen_text(value: &Value, sentinel: &str) {
    assert!(!value.to_string().contains(sentinel));
    match value {
        Value::Object(fields) => {
            for value in fields.values() {
                assert_no_screen_text(value, sentinel);
            }
        }
        Value::Array(items) => {
            // Opaque journal material is JSON encoded as byte arrays; inspect
            // those bytes too, rather than mistaking their decimal form for redaction.
            if let Ok(bytes) = serde_json::from_value::<Vec<u8>>(value.clone()) {
                let text = String::from_utf8_lossy(&bytes);
                assert!(
                    !text.contains(sentinel),
                    "screen text in opaque journal material"
                );
            }
            for value in items {
                assert_no_screen_text(value, sentinel);
            }
        }
        _ => {}
    }
}

#[tokio::test]
async fn no_image_read_writes_one_text_free_row() {
    const LABEL: &str = "PrivateDiscordMessage_f74ba901";
    let management = granted_management().await;
    let source = FixtureSource::new(vec![RawElement::fixture(1, "AXWindow")
        .titled(LABEL)
        .with_children(vec![RawElement::fixture(2, "AXButton").titled(LABEL)])]);
    source
        .0
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .unreadable_subtrees = 2;
    let storage = cerebellum_core::journal::InMemoryJournalStorage::new();
    let plane: Plane = ComputerPlane::with_result_schema_enforcement(
        support::computer::audit_with_storage(storage.clone()),
        ResultSchemaEnforcement::Withhold,
    )
    .with_permission_liveness(super::support::computer::live_permissions())
    .with_app_state_source(source);
    let before = plane.journal_entry_count().await;
    let reply = serve(
        &plane,
        &management,
        "conversation-1",
        no_relay(),
        json!({"target": TARGET_BUNDLE_ID, "include_image": false}),
        InMemoryCaptureBackend::default(),
    )
    .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert!(reply["state_text"].as_str().unwrap().contains(LABEL));
    assert_eq!(plane.journal_entry_count().await, before + 1);
    let row = recorded_read(&storage);
    assert_eq!(row["phase"], "finalized");
    let material: Vec<u8> = serde_json::from_value(row["dispatch_material"].clone()).unwrap();
    let target: Value = serde_json::from_slice(&material).unwrap();
    assert_eq!(target, serde_json::to_value(grant()).unwrap());
    let result: Vec<u8> = serde_json::from_value(row["completed_result"].clone()).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&result).unwrap(),
        json!({
            "element_count": 2, "unreadable_subtrees": 2, "image_returned": false,
            "routes": {"public": 0, "skylight": 0},
            "release_routes": {"public": 0, "skylight": 0},
            "auth": "not_applicable",
        })
    );
    assert_no_screen_text(&row, LABEL);
    assert!(reply.get("manual_accessibility").is_none());
}

#[tokio::test]
async fn failed_read_journal_withholds_tree_and_image() {
    const LABEL: &str = "DoNotReleaseUnjournaledMessage_f92a";
    let management = granted_management().await;
    for include_image in [false, true] {
        let plane: Plane<_> = ComputerPlane::with_result_schema_enforcement(
            support::computer::failing_audit(),
            ResultSchemaEnforcement::Withhold,
        )
        .with_permission_liveness(super::support::computer::live_permissions())
        .with_app_state_source(FixtureSource::new(vec![
            RawElement::fixture(1, "AXWindow").titled(LABEL)
        ]));
        let reply = serve(
            &plane,
            &management,
            "conversation-1",
            no_relay(),
            json!({"target": TARGET_BUNDLE_ID, "include_image": include_image}),
            capturing(jpeg(1250, 750, 0)),
        )
        .await;
        assert_eq!(reply["outcome"], "audit_unavailable", "{reply}");
        assert!(reply.get("state_text").is_none());
        assert!(reply.get("image").is_none());
        assert!(!reply.to_string().contains(LABEL));
        assert!(plane.result_schema_findings().is_empty());
    }
}

#[tokio::test]
async fn image_and_empty_reads_use_the_same_single_summary_row() {
    let management = granted_management().await;
    for (include_image, unreadable) in [(true, false), (false, true)] {
        let source = FixtureSource::new(vec![RawElement::fixture(1, "AXWindow")]);
        if unreadable {
            *source.0.lock().unwrap() = Err(AppStateReadError::Unreadable);
        }
        let storage = cerebellum_core::journal::InMemoryJournalStorage::new();
        let plane: Plane = ComputerPlane::with_result_schema_enforcement(
            support::computer::audit_with_storage(storage.clone()),
            ResultSchemaEnforcement::Withhold,
        )
        .with_permission_liveness(super::support::computer::live_permissions())
        .with_app_state_source(source)
        .with_image_freshness_source(Arc::new(FixtureFreshness {
            repaints: false,
            before:
                cerebellum::computer_capability::image_freshness::WindowVisibility::FullyVisible,
            after: cerebellum::computer_capability::image_freshness::WindowVisibility::FullyVisible,
            seen: Mutex::new(vec![]),
        }));
        let before = plane.journal_entry_count().await;
        let reply = serve(
            &plane,
            &management,
            "conversation-1",
            no_relay(),
            json!({"target": TARGET_BUNDLE_ID, "include_image": include_image}),
            capturing(jpeg(1250, 750, 0)),
        )
        .await;
        assert_eq!(reply["outcome"], "completed", "{reply}");
        assert_eq!(reply.get("image").is_some(), include_image);
        assert_eq!(plane.journal_entry_count().await, before + 1);
        let row = recorded_read(&storage);
        assert_eq!(row["phase"], "finalized");
        let result: Vec<u8> = serde_json::from_value(row["completed_result"].clone()).unwrap();
        let mut expected = json!({
            "element_count": if unreadable {0} else {1},
            "unreadable_subtrees": 1,
            "image_returned": include_image,
            "routes": {"public": 0, "skylight": 0},
            "release_routes": {"public": 0, "skylight": 0},
            "auth": "not_applicable",
        });
        if include_image {
            expected["image_decision"] = json!("fully_visible");
        }
        assert_eq!(serde_json::from_slice::<Value>(&result).unwrap(), expected,);
    }
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn serialized_read_row_has_all_four_desk_check_fields() {
    struct ReportingSource(Arc<FixtureSource>);
    impl AppStateSource for ReportingSource {
        fn read_app_state(
            &self,
            target: &ProcessGrant,
            bounds: ReadBounds,
        ) -> Result<RawAppState, AppStateReadError> {
            cerebellum_macos::ManualAccessibilityScope::record(
                target.pid,
                cerebellum_macos::ManualAccessibility::NewlyEnabled,
            );
            self.0.read_app_state(target, bounds)
        }
    }
    let management = granted_management().await;
    let storage = cerebellum_core::journal::InMemoryJournalStorage::new();
    let source = FixtureSource::new(vec![RawElement::fixture(1, "AXWindow")]);
    source
        .0
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .unreadable_subtrees = 3;
    let plane: Plane = ComputerPlane::with_result_schema_enforcement(
        support::computer::audit_with_storage(storage.clone()),
        ResultSchemaEnforcement::Withhold,
    )
    .with_permission_liveness(super::support::computer::live_permissions())
    .with_app_state_source(Arc::new(ReportingSource(source)));
    let reply = serve(
        &plane,
        &management,
        "conversation-1",
        no_relay(),
        json!({"target": TARGET_BUNDLE_ID}),
        InMemoryCaptureBackend::default(),
    )
    .await;
    assert_eq!(reply["outcome"], "completed");
    assert!(reply.get("manual_accessibility").is_none());
    let row = recorded_read(&storage);
    assert_eq!(row["element_count"].as_u64(), Some(1));
    // Count three source-reported gaps plus one unpopulated window.
    assert_eq!(row["unreadable_subtrees"].as_u64(), Some(4));
    assert_eq!(row["image_returned"].as_bool(), Some(false));
    assert_eq!(row["manual_accessibility"].as_str(), Some("newly_enabled"));
    assert!(row.get("unreadable_count").is_none());
}
