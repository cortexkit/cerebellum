//! `computer.read_state` served through the plane: the tree, its ids across
//! conversations, and the window image, each checked against the row's
//! result schema in withholding mode, so a reply the vocabulary does not
//! declare fails here rather than reaching a caller.

mod support;

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
        .with_app_state_source(source)
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

fn ids(tree: &str) -> Vec<String> {
    tree.lines()
        .map(|line| line.split_whitespace().next().unwrap().to_string())
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
    let tree = reply["tree"].as_str().unwrap();
    assert!(line_with(tree, "text area").ends_with("\"Message @IceTea\" [settable]"));
    let sheet = line_with(tree, "sheet \"GoToWindow\"");
    assert!(
        sheet.starts_with("  s"),
        "the sheet is not under its window: {sheet}"
    );
    assert!(line_with(tree, "PathTextField").starts_with("    s"));
    assert!(!tree.contains("SECRET_SENTINEL"), "{tree}");
    assert_eq!(reply["unreadable_subtrees"], 0);
    assert!(reply.get("image").is_none() && reply.get("image_unavailable").is_none());
    assert!(plane.result_schema_findings().is_empty());
}

/// Filters narrow the reply and keep the ancestor path; a subtree id this
/// session does not hold is refused as stale.
#[tokio::test]
async fn filters_and_a_stale_subtree_id_are_served_through_withholding() {
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
    let tree = reply["tree"].as_str().unwrap();
    assert_eq!(tree.lines().count(), 3, "{tree}");

    let stale = serve(
        &plane,
        &management,
        "conversation-1",
        no_relay(),
        json!({"target": TARGET_BUNDLE_ID, "subtree_element_id": "sgone1-4"}),
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
        ids(first["tree"].as_str().unwrap()),
        ids(second["tree"].as_str().unwrap()),
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
        json!({"target": TARGET_BUNDLE_ID, "subtree_element_id": first[1]}),
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
fn jpeg(width: u16, height: u16, padding: usize) -> Vec<u8> {
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
fn capturing(image: Vec<u8>) -> InMemoryCaptureBackend {
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
        assert!(reply["tree"].as_str().unwrap().contains("GoToWindow"));
        assert!(reply.get("image").is_none(), "{reason}: {reply}");
        assert_eq!(reply["image_unavailable"]["reason"], reason, "{reply}");
    }
    assert!(plane.result_schema_findings().is_empty());

    // A journal that cannot record the capture releases no image.
    let failing: Plane<_> = ComputerPlane::with_result_schema_enforcement(
        support::computer::failing_audit(),
        ResultSchemaEnforcement::Withhold,
    )
    .with_app_state_source(FixtureSource::new(vec![chat_window()]));
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
    assert_eq!(
        reply["image_unavailable"]["reason"], "audit_unavailable",
        "{reply}"
    );
    assert!(reply["tree"].as_str().unwrap().contains("GoToWindow"));
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

    source.replace(vec![chat_window()]);
    assert!(plane.result_schema_findings().is_empty());
}

/// Without the app grant and with nobody to ask, the read refuses the way
/// every consent-needing row does, and reads nothing.
#[tokio::test]
async fn an_ungranted_read_is_refused_before_anything_is_read() {
    let management = support::computer::management();
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
    assert_eq!(reply["outcome"], "consent_unavailable", "{reply}");
    assert!(reply.get("tree").is_none());
    assert_eq!(management.app_state_sessions().session_count(), 0);
}
