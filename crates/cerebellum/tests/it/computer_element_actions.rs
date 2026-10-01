//! The element actions served through the plane: pressing an element by id,
//! pressing whatever a point in a returned image lands on, and writing text
//! into an element. Every reply is checked against its row's result schema in
//! withholding mode, and every assertion about what was done reads the
//! fixture's record of presses and writes rather than the reply.

use super::support;

use std::sync::Arc;

use cerebellum::computer_capability::{
    servable, ComputerPlane, ResultSchemaEnforcement, ServeContext,
};
use cerebellum::computer_grants::{ConsentContext, GrantCaller, QuestionCarrier};
use cerebellum::management::ManagementPlane;
use cerebellum_computer::app_state::source::{ElementFacts, HitScope, RawElement, TextAttribute};
use cerebellum_computer::capture::{EnumeratedWindow, InMemoryCaptureBackend, WindowFrame};
use cerebellum_computer::platform::{ProcessGrant, TargetResolution};
use cerebellum_core::clock::FakeClock;
use cerebellum_core::journal::{InMemoryJournalStorage, JournalIdentity, JournalStorage};
use serde_json::{json, Value};
use support::computer::{
    audit, facts, grant, granted_management, identity, no_relay, Desk, DeskElement,
    MutableTargetResolver, ScriptedCarrier, TestRedactor, GRANTEE, TARGET_BUNDLE_ID,
};

type Plane<S = InMemoryJournalStorage> = ComputerPlane<
    InMemoryCaptureBackend,
    TestRedactor,
    cerebellum_core::journal::ValidatedSeverityTaxonomy,
    S,
>;

// Point-action fixtures capture fake windows, whose visibility cannot be read
// from the real desktop. Certify only the fixture's fully visible window.
struct VisibleFixture;
impl cerebellum::computer_capability::image_freshness::ImageFreshnessSource for VisibleFixture {
    fn inspect(
        &self,
        _: &ProcessGrant,
        _: Option<&str>,
    ) -> (
        bool,
        cerebellum::computer_capability::image_freshness::WindowVisibility,
    ) {
        (
            false,
            cerebellum::computer_capability::image_freshness::WindowVisibility::FullyVisible,
        )
    }
}

fn plane(desk: &Desk) -> Plane {
    ComputerPlane::with_result_schema_enforcement(audit(), ResultSchemaEnforcement::Withhold)
        .with_app_state_source(desk.source())
        .with_image_freshness_source(Arc::new(VisibleFixture))
}

async fn serve_as<S: JournalStorage + Send + 'static>(
    plane: &Plane<S>,
    management: &Arc<ManagementPlane>,
    identity: JournalIdentity,
    consent: ConsentContext,
    name: &str,
    arguments: Value,
    backend: InMemoryCaptureBackend,
) -> Value {
    let clock = FakeClock::new();
    plane
        .serve(
            servable(name).expect("the capability is served"),
            &arguments,
            ServeContext {
                cancel: cerebellum::CancelHandle::for_uninterruptible_probe(),
                grantee: GRANTEE,
                identity,
                management,
                consent,
                clock: &clock,
                now_ms: 10,
            },
            move |_| backend,
        )
        .await
        .unwrap_or_else(|error| panic!("{name} replied outside its row: {error:?}"))
}

async fn serve(
    plane: &Plane,
    management: &Arc<ManagementPlane>,
    name: &str,
    arguments: Value,
) -> Value {
    serve_as(
        plane,
        management,
        identity(),
        no_relay(),
        name,
        arguments,
        InMemoryCaptureBackend::default(),
    )
    .await
}

/// A window with a Send button, a label that cannot be pressed and a text
/// field, and a menu bar whose File menu holds a Log Out item. The Log Out
/// item is numbered but never shown, which is what makes a press on its id a
/// press on a session-ending item.
fn window_and_menus() -> Vec<RawElement> {
    vec![
        RawElement::fixture(1, "AXWindow")
            .titled("Chat")
            .with_children(vec![
                RawElement::fixture(10, "AXButton").titled("Send"),
                RawElement::fixture(11, "AXStaticText").titled("Hello"),
                RawElement::fixture(12, "AXTextField").titled("Composer"),
            ]),
        RawElement::fixture(30, "AXMenuBar").with_children(vec![
            RawElement::fixture(31, "AXMenuBarItem").titled("Apple"),
            RawElement::fixture(32, "AXMenuBarItem")
                .titled("File")
                .with_children(vec![RawElement::fixture(33, "AXMenu").with_children(vec![
                    RawElement::fixture(34, "AXMenuItem").titled("Log Out Jane…"),
                    RawElement::fixture(35, "AXMenuItem").titled("Save"),
                ])]),
        ]),
    ]
}

/// The same window after the Send button was pressed: a new label appears.
fn after_send() -> Vec<RawElement> {
    let mut roots = window_and_menus();
    roots[0]
        .children
        .push(RawElement::fixture(13, "AXStaticText").titled("Sent"));
    roots
}

fn desk() -> Desk {
    Desk::new(window_and_menus())
        .with_element(
            10,
            DeskElement {
                facts: facts("AXButton", &["AXPress", "AXShowMenu"]),
                ..DeskElement::default()
            },
        )
        .with_element(
            11,
            DeskElement {
                facts: facts("AXStaticText", &["AXShowMenu", "Name:open\nfake"]),
                ..DeskElement::default()
            },
        )
        .with_element(
            12,
            DeskElement {
                facts: ElementFacts {
                    value_settable: true,
                    selected_text_settable: true,
                    ..facts("AXTextField", &[])
                },
                value: Some("hello world".into()),
                selection: Some((5, 0)),
                applies_writes: true,
                ..DeskElement::default()
            },
        )
}

/// The ids of a read, by the label that follows each.
fn id_of(tree: &str, needle: &str) -> String {
    tree.lines()
        .find(|line| line.contains(needle))
        .unwrap_or_else(|| panic!("no line with {needle} in\n{tree}"))
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

/// The window's outline and the menu bar, which the outline names in one
/// line and a zoom prints whole.
async fn read(plane: &Plane, management: &Arc<ManagementPlane>) -> String {
    let mut tree = String::new();
    for arguments in [
        json!({"target": TARGET_BUNDLE_ID}),
        json!({"target": TARGET_BUNDLE_ID, "zoom": "menubar"}),
    ] {
        let reply = serve(plane, management, "computer.read_state", arguments).await;
        tree.push_str(
            reply["state_text"]
                .as_str()
                .expect("the read returns its state as text"),
        );
    }
    tree
}

/// The ids an action reply's diff names as `added` (`+` lines), `changed`
/// (`~` lines) or `removed` (the ranges after `Removed element IDs:`).
fn ids(reply: &Value, field: &str) -> Vec<String> {
    let text = reply["state_text"]
        .as_str()
        .unwrap_or_else(|| panic!("the diff is missing from {reply}"));
    let first_word = |line: &str| line[1..].split_whitespace().next().unwrap().to_string();
    match field {
        "added" => text.lines().filter(|line| line.starts_with('+')).map(first_word).collect(),
        "changed" => text.lines().filter(|line| line.starts_with('~')).map(first_word).collect(),
        "removed" => text
            .lines()
            .filter_map(|line| line.strip_prefix("Removed element IDs: "))
            .flat_map(|ranges| ranges.split(", "))
            .flat_map(|range| match range.split_once('-') {
                Some((start, end)) => {
                    let (start, end): (u64, u64) = (start.parse().unwrap(), end.parse().unwrap());
                    (start..=end).map(|id| id.to_string()).collect::<Vec<_>>()
                }
                None => vec![range.to_string()],
            })
            .collect(),
        _ => unreachable!("no diff field {field}"),
    }
}

// ---------------------------------------------------------------------------
// press_element
// ---------------------------------------------------------------------------

/// A live id is pressed through accessibility, and the reply carries the
/// diff that followed: the label the press made appear is named as added.
#[tokio::test]
async fn pressing_a_live_element_presses_it_and_returns_the_diff() {
    let desk = desk();
    desk.state().after_action = Some(after_send());
    let plane = plane(&desk);
    let management = granted_management().await;
    let tree = read(&plane, &management).await;
    let send = id_of(&tree, " button Send");
    let journaled = plane.journal_entry_count().await;

    let reply = serve(
        &plane,
        &management,
        "computer.press_element",
        json!({"element_id": send}),
    )
    .await;

    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(desk.state().presses, vec![10]);
    assert_eq!(ids(&reply, "added").len(), 1, "{reply}");
    assert!(ids(&reply, "changed").is_empty() && ids(&reply, "removed").is_empty());
    assert_eq!(reply["unreadable_subtrees"], 0);
    assert!(plane.journal_entry_count().await > journaled);
    assert!(plane.result_schema_findings().is_empty());
}

/// A press that changes nothing is still a press: the empty diff is reported
/// as it is, after the settle bound, not turned into a failure.
#[tokio::test]
async fn a_press_that_changes_nothing_reports_an_empty_diff() {
    let desk = desk();
    let plane = plane(&desk);
    let management = granted_management().await;
    let tree = read(&plane, &management).await;
    let reply = serve(
        &plane,
        &management,
        "computer.press_element",
        json!({"element_id": id_of(&tree, " button Send")}),
    )
    .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    for field in ["changed", "added", "removed"] {
        assert!(ids(&reply, field).is_empty(), "{field}: {reply}");
    }
}

/// An id this conversation's session never issued is stale, and nothing is
/// pressed.
#[tokio::test]
async fn pressing_a_stale_id_refuses_and_presses_nothing() {
    let desk = desk();
    let plane = plane(&desk);
    let management = granted_management().await;
    let tree = read(&plane, &management).await;
    // An id in the old shape, and a number this session never issued.
    for stale in ["sgone1-4", "999999"] {
        let reply = serve(
            &plane,
            &management,
            "computer.press_element",
            json!({"element_id": stale}),
        )
        .await;
        assert_eq!(reply["outcome"], "stale_element", "{reply}");
        assert!(reply["remedy"].as_str().unwrap().contains("read_state"));
    }
    assert!(desk.state().presses.is_empty());
}

/// The id of a session-ending menu item is never shown, but it exists; a
/// press on it is refused by name and nothing is pressed. Its neighbours are
/// checked in the tree first, so the id pressed is known to be the hidden one.
#[tokio::test]
async fn pressing_a_session_ending_menu_item_is_refused() {
    let desk = desk();
    let plane = plane(&desk);
    let management = granted_management().await;
    let tree = read(&plane, &management).await;
    let menu = tree
        .lines()
        .find(|line| line.ends_with(" menu"))
        .and_then(|line| line.split_whitespace().next())
        .unwrap_or_else(|| panic!("no menu line in\n{tree}"));
    let save = id_of(&tree, " menu item Save");
    let menu_number: u64 = menu.parse().unwrap();
    assert_eq!(save, (menu_number + 2).to_string(), "{tree}");
    let log_out = (menu_number + 1).to_string();
    assert!(
        !tree.lines().any(|line| line.trim_start().starts_with(&format!("{log_out} ")))
            && !tree.contains("Log Out"),
        "{tree}"
    );

    let reply = serve(
        &plane,
        &management,
        "computer.press_element",
        json!({"element_id": log_out}),
    )
    .await;
    assert_eq!(reply["outcome"], "blocked_menu_item", "{reply}");
    assert!(desk.state().presses.is_empty());
}

/// An element with no press refuses by name, the refusal names the standard
/// actions it does offer and counts the rest without quoting them, and the
/// pointer is never used in its place.
#[tokio::test]
async fn an_element_without_a_press_names_what_it_supports() {
    let desk = desk();
    let plane = plane(&desk);
    let management = granted_management().await;
    let tree = read(&plane, &management).await;
    let reply = serve(
        &plane,
        &management,
        "computer.press_element",
        json!({"element_id": id_of(&tree, " text Hello")}),
    )
    .await;
    assert_eq!(reply["outcome"], "no_press_action", "{reply}");
    let remedy = reply["remedy"].as_str().unwrap();
    assert!(
        remedy.contains("AXShowMenu") && remedy.contains("1 custom"),
        "{remedy}"
    );
    assert!(
        !remedy.contains("fake"),
        "application text reached a remedy: {remedy}"
    );
    assert!(desk.state().presses.is_empty());
    assert!(desk.state().hit_scopes.is_empty());
}

/// When the application restarts after the read, its ids name nothing: the
/// process generation is checked again before acting.
#[tokio::test]
async fn an_id_from_an_ended_process_generation_is_stale() {
    let desk = desk();
    let plane = plane(&desk);
    let resolver = Arc::new(MutableTargetResolver::new(TargetResolution::Resolved(
        grant(),
    )));
    let management = support::computer::management_with(resolver.clone());
    support::computer::grant_app(&management).await;
    let tree = read(&plane, &management).await;
    resolver.replace(TargetResolution::Resolved(ProcessGrant {
        process_generation_evidence: "1700000000000999".into(),
        ..grant()
    }));
    let reply = serve(
        &plane,
        &management,
        "computer.press_element",
        json!({"element_id": id_of(&tree, " button Send")}),
    )
    .await;
    assert_eq!(reply["outcome"], "stale_element", "{reply}");
    assert!(desk.state().presses.is_empty());
}

// ---------------------------------------------------------------------------
// press_point
// ---------------------------------------------------------------------------

/// A minimal JPEG: start of image, one frame header, end of image.
fn jpeg(width: u16, height: u16) -> Vec<u8> {
    let mut bytes = vec![0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x0B, 0x08];
    bytes.extend_from_slice(&height.to_be_bytes());
    bytes.extend_from_slice(&width.to_be_bytes());
    bytes.extend_from_slice(&[0x01, 0x01, 0x11, 0x00, 0xFF, 0xD9]);
    bytes
}

/// One window of the fixture application at (100, 50), 1000 by 600 points,
/// captured at 2000 by 1200 and scaled to 1250 by 750.
fn capturing() -> InMemoryCaptureBackend {
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
    backend.set_vision_frame("77", 2000, 1200, jpeg(1250, 750));
    backend
}

async fn read_with_image(plane: &Plane, management: &Arc<ManagementPlane>) -> String {
    let reply = serve_as(
        plane,
        management,
        identity(),
        no_relay(),
        "computer.read_state",
        json!({"target": TARGET_BUNDLE_ID, "include_image": true}),
        capturing(),
    )
    .await;
    reply["image"]["image_id"]
        .as_str()
        .unwrap_or_else(|| panic!("no image in {reply}"))
        .to_string()
}

/// The point is hit-tested inside the image's own application, never
/// system-wide: here another application's window covers the point, and a
/// system-wide hit would land in it. The element found is pressed, the pointer
/// is not used, and the element is given an id the diff can name.
#[tokio::test]
async fn a_point_is_hit_tested_in_its_own_application_and_pressed() {
    let desk = desk();
    {
        let mut state = desk.state();
        state.application_hit = Some((60, Some(grant().pid)));
        state.system_wide_hit = Some((99, Some(777)));
        state.elements.insert(
            60,
            DeskElement {
                facts: facts("AXButton", &["AXPress"]),
                ..DeskElement::default()
            },
        );
        let mut after = window_and_menus();
        after[0]
            .children
            .push(RawElement::fixture(60, "AXButton").titled("Attach"));
        state.after_action = Some(after);
    }
    let plane = plane(&desk);
    let management = granted_management().await;
    let image_id = read_with_image(&plane, &management).await;

    let reply = serve(
        &plane,
        &management,
        "computer.press_point",
        json!({"image_id": image_id, "x": 625, "y": 125}),
    )
    .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(desk.state().presses, vec![60]);
    assert_eq!(
        desk.state().hit_scopes,
        vec![HitScope::Application { pid: grant().pid }]
    );
    assert_eq!(ids(&reply, "added").len(), 1, "{reply}");
    assert!(plane.result_schema_findings().is_empty());
}

/// A hit belonging to another process is no hit, and nothing is pressed.
#[tokio::test]
async fn a_hit_owned_by_another_process_is_no_element() {
    let desk = desk();
    desk.state().application_hit = Some((50, Some(999)));
    let plane = plane(&desk);
    let management = granted_management().await;
    let image_id = read_with_image(&plane, &management).await;
    let reply = serve(
        &plane,
        &management,
        "computer.press_point",
        json!({"image_id": image_id, "x": 10, "y": 10}),
    )
    .await;
    assert_eq!(reply["outcome"], "no_element_at_point", "{reply}");
    assert!(desk.state().presses.is_empty());
}

/// Nothing at the point refuses by name; so do an unknown image and a point
/// outside the image, before any hit test.
#[tokio::test]
async fn nothing_at_the_point_an_unknown_image_and_an_outside_point_are_refused() {
    let desk = desk();
    let plane = plane(&desk);
    let management = granted_management().await;
    let image_id = read_with_image(&plane, &management).await;

    let nothing = serve(
        &plane,
        &management,
        "computer.press_point",
        json!({"image_id": image_id, "x": 10, "y": 10}),
    )
    .await;
    assert_eq!(nothing["outcome"], "no_element_at_point", "{nothing}");
    let scopes_after_one_hit = desk.state().hit_scopes.len();

    let outside = serve(
        &plane,
        &management,
        "computer.press_point",
        json!({"image_id": image_id, "x": 1250, "y": 10}),
    )
    .await;
    assert_eq!(outside["outcome"], "point_out_of_bounds", "{outside}");
    let unknown = serve(
        &plane,
        &management,
        "computer.press_point",
        json!({"image_id": "inosuch1", "x": 1, "y": 1}),
    )
    .await;
    assert_eq!(unknown["outcome"], "image_reference_unknown", "{unknown}");
    assert_eq!(desk.state().hit_scopes.len(), scopes_after_one_hit);
    assert!(desk.state().presses.is_empty());
}

/// A hit on a session-ending menu item, which no tree ever showed, is
/// recognised at press time and refused.
#[tokio::test]
async fn a_hit_on_a_session_ending_item_is_refused_at_press_time() {
    let desk = desk();
    {
        let mut state = desk.state();
        state.application_hit = Some((70, Some(grant().pid)));
        let mut item = facts("AXMenuItem", &["AXPress"]);
        item.title = Some("Shut Down…".into());
        state.elements.insert(
            70,
            DeskElement {
                facts: item,
                ..DeskElement::default()
            },
        );
    }
    let plane = plane(&desk);
    let management = granted_management().await;
    let image_id = read_with_image(&plane, &management).await;
    let reply = serve(
        &plane,
        &management,
        "computer.press_point",
        json!({"image_id": image_id, "x": 5, "y": 5}),
    )
    .await;
    assert_eq!(reply["outcome"], "blocked_menu_item", "{reply}");
    assert!(desk.state().presses.is_empty());
}

// ---------------------------------------------------------------------------
// write_text
// ---------------------------------------------------------------------------

async fn write(
    plane: &Plane,
    management: &Arc<ManagementPlane>,
    element_id: &str,
    text: &str,
    mode: &str,
) -> Value {
    serve(
        plane,
        management,
        "computer.write_text",
        json!({"element_id": element_id, "text": text, "write_mode": mode}),
    )
    .await
}

#[tokio::test]
async fn web_content_refuses_without_calling_value_or_selection_setter() {
    for mode in ["replace_value", "insert_at_caret"] {
        let desk = desk();
        {
            let mut state = desk.state();
            let fields = std::mem::take(&mut state.roots[0].children);
            state.roots[0].children =
                vec![RawElement::fixture(90, "AXWebArea").with_children(vec![
                    RawElement::fixture(91, "AXGroup").with_children(fields),
                ])];
        }
        let plane = plane(&desk);
        let management = granted_management().await;
        let tree = read(&plane, &management).await;
        let reply = write(
            &plane,
            &management,
            &id_of(&tree, "Composer"),
            "draft",
            mode,
        )
        .await;
        assert!(
            desk.state().writes.is_empty(),
            "web editor setter was called"
        );
        assert_eq!(reply["reason"], "web_content_needs_type", "{reply}");
        assert_eq!(reply["outcome"], "web_content_needs_type", "{reply}");
        assert!(reply["remedy"].as_str().unwrap().contains("press_element"));
    }
}

/// replace_value sets the whole value and is confirmed by reading it back.
#[tokio::test]
async fn replace_writes_the_value_and_confirms_it() {
    let desk = desk();
    let plane = plane(&desk);
    let management = granted_management().await;
    let tree = read(&plane, &management).await;
    let reply = write(
        &plane,
        &management,
        &id_of(&tree, "Composer"),
        "draft",
        "replace_value",
    )
    .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(reply["effect_status"], "effect_observed");
    assert_eq!(desk.state().writes, vec![(12, TextAttribute::Value)]);
    assert_eq!(desk.state().elements[&12].value.as_deref(), Some("draft"));
    assert!(
        reply.get("state_text").is_some(),
        "the diff is missing: {reply}"
    );
}

/// insert_at_caret replaces the selection, and is confirmed against the
/// value the selection actually present predicts.
#[tokio::test]
async fn insert_writes_at_the_caret_and_confirms_it() {
    let desk = desk();
    let plane = plane(&desk);
    let management = granted_management().await;
    let tree = read(&plane, &management).await;
    let reply = write(
        &plane,
        &management,
        &id_of(&tree, "Composer"),
        ",",
        "insert_at_caret",
    )
    .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(desk.state().writes, vec![(12, TextAttribute::SelectedText)]);
    assert_eq!(
        desk.state().elements[&12].value.as_deref(),
        Some("hello, world")
    );
}

/// A secure field is refused before anything is written.
#[tokio::test]
async fn a_secure_field_is_refused_before_any_write() {
    let desk = desk();
    desk.state().elements.get_mut(&12).unwrap().facts.subrole = Some("AXSecureTextField".into());
    let plane = plane(&desk);
    let management = granted_management().await;
    let tree = read(&plane, &management).await;
    let reply = write(
        &plane,
        &management,
        &id_of(&tree, "Composer"),
        "hunter2",
        "replace_value",
    )
    .await;
    assert_eq!(reply["outcome"], "secure_field_refused", "{reply}");
    assert!(desk.state().writes.is_empty());
}

/// An element whose text cannot be written refuses, naming type as the way
/// to reach it.
#[tokio::test]
async fn a_field_that_cannot_be_written_names_type() {
    let desk = desk();
    let plane = plane(&desk);
    let management = granted_management().await;
    let tree = read(&plane, &management).await;
    let reply = write(
        &plane,
        &management,
        &id_of(&tree, " button Send"),
        "x",
        "replace_value",
    )
    .await;
    assert_eq!(reply["outcome"], "element_not_settable", "{reply}");
    assert!(reply["remedy"].as_str().unwrap().contains("type"));
    assert!(desk.state().writes.is_empty());
}

/// An application that updates its value a moment after accepting the write
/// is confirmed once the value shows,
/// not reported unconfirmed on the first read.
#[tokio::test]
async fn a_value_that_lands_after_a_delay_is_confirmed() {
    let desk = desk();
    {
        let mut state = desk.state();
        let composer = state.elements.get_mut(&12).unwrap();
        let before = composer.value.clone();
        composer.readbacks = [before.clone(), before].into_iter().collect();
    }
    let plane = plane(&desk);
    let management = granted_management().await;
    let tree = read(&plane, &management).await;
    let reply = write(
        &plane,
        &management,
        &id_of(&tree, "Composer"),
        "draft",
        "replace_value",
    )
    .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(reply["effect_status"], "effect_observed");
    assert_eq!(desk.state().writes.len(), 1, "exactly one attempt");
}

/// An application that accepts the write and keeps its old value is not
/// reported as written: the reply is unconfirmed, and the text is not echoed
/// anywhere in it.
#[tokio::test]
async fn a_read_back_that_does_not_match_is_unconfirmed_and_never_completed() {
    const TEXT: &str = "text-that-must-not-echo";
    let desk = desk();
    desk.state().elements.get_mut(&12).unwrap().applies_writes = false;
    let plane = plane(&desk);
    let management = granted_management().await;
    let tree = read(&plane, &management).await;
    let reply = write(
        &plane,
        &management,
        &id_of(&tree, "Composer"),
        TEXT,
        "replace_value",
    )
    .await;
    assert_eq!(reply["outcome"], "delivery_unconfirmed", "{reply}");
    assert_eq!(reply["effect_status"], "effect_indeterminate");
    assert!(!reply.to_string().contains(TEXT), "{reply}");
    assert_eq!(desk.state().writes.len(), 1, "exactly one attempt");
}

/// An insert whose caret cannot be read writes nothing.
#[tokio::test]
async fn an_insert_without_a_readable_caret_writes_nothing() {
    let desk = desk();
    desk.state().elements.get_mut(&12).unwrap().selection = None;
    let plane = plane(&desk);
    let management = granted_management().await;
    let tree = read(&plane, &management).await;
    let reply = write(
        &plane,
        &management,
        &id_of(&tree, "Composer"),
        "x",
        "insert_at_caret",
    )
    .await;
    assert_eq!(reply["outcome"], "caret_position_unknown", "{reply}");
    assert!(reply["remedy"].as_str().unwrap().contains("replace_value"));
    assert!(desk.state().writes.is_empty());
}

// ---------------------------------------------------------------------------
// The journal never holds written text
// ---------------------------------------------------------------------------

/// Every string the journal's serialized state holds, however it is encoded.
///
/// Journal byte fields are base64, and inside a decoded record the material
/// fields are JSON arrays of byte values, so a secret can sit two encodings
/// deep. A plain search of the serialized state would miss both and pass for
/// the wrong reason; each decoded layer is searched again until nothing new
/// decodes.
fn journal_strings(text: &str) -> Vec<String> {
    let mut found = vec![text.to_string()];
    let mut index = 0;
    while index < found.len() {
        let current = found[index].clone();
        found.extend(base64_layers(&current));
        found.extend(byte_array_layers(&current));
        index += 1;
    }
    found
}

fn base64_layers(text: &str) -> Vec<String> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    for token in
        text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='))
    {
        if token.len() < 8 {
            continue;
        }
        let (mut buffer, mut accumulator, mut bits) = (Vec::new(), 0u32, 0u32);
        let mut usable = true;
        for byte in token.bytes().take_while(|b| *b != b'=') {
            let Some(index) = ALPHABET.iter().position(|c| *c == byte) else {
                usable = false;
                break;
            };
            accumulator = (accumulator << 6) | index as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                buffer.push((accumulator >> bits) as u8);
            }
        }
        if usable {
            if let Ok(decoded) = String::from_utf8(buffer) {
                if decoded != token {
                    out.push(decoded);
                }
            }
        }
    }
    out
}

/// The text of every `[n,n,...]` array of byte values in `text`.
fn byte_array_layers(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for piece in text.split('[').skip(1) {
        let Some(body) = piece.split(']').next() else {
            continue;
        };
        let bytes: Option<Vec<u8>> = body
            .split(',')
            .map(|number| number.trim().parse::<u8>().ok())
            .collect();
        if let Some(bytes) = bytes.filter(|bytes| bytes.len() >= 4) {
            if let Ok(decoded) = String::from_utf8(bytes) {
                out.push(decoded);
            }
        }
    }
    out
}

fn journal_contains(storage: &InMemoryJournalStorage, needle: &str) -> bool {
    let state = storage.load().expect("the journal loads");
    let serialized = serde_json::to_string(&state).expect("the journal serializes");
    journal_strings(&serialized)
        .iter()
        .any(|text| text.contains(needle))
}

/// Written and typed text never reach the journal, and the scan that says so is
/// first shown to find a planted positive in the same journal: the
/// application's bundle identity carries a marker, and the journal records
/// the grant it acted under, so a scan that cannot find the marker cannot be
/// trusted to report the secret absent.
#[tokio::test]
async fn written_and_typed_text_never_reach_the_journal() {
    const PLANTED: &str = "PlantedPositive7f3a";
    const SECRET: &str = "Sw0rdf1sh-written-secret";
    let target = ProcessGrant {
        bundle_identity: format!("com.example.{PLANTED}"),
        ..grant()
    };
    let management = support::computer::management_with(Arc::new(support::computer::Fixed(
        TargetResolution::Resolved(target.clone()),
    )));
    let storage = InMemoryJournalStorage::new();
    let plane: Plane = ComputerPlane::with_result_schema_enforcement(
        support::computer::audit_with_storage(storage.clone()),
        ResultSchemaEnforcement::Withhold,
    )
    .with_app_state_source(desk().source());
    let carrier = ScriptedCarrier::answering(&["allow_conversation"]);
    let consent = || {
        let (drain_sender, drain) = tokio::sync::watch::channel(false);
        std::mem::forget(drain_sender);
        ConsentContext::new(
            GrantCaller {
                conversation_key: identity().conversation_key,
                agent_project_id: GRANTEE.into(),
                durable_identity_attested: false,
            },
            Some(Arc::new(carrier.clone()) as Arc<dyn QuestionCarrier>),
            Arc::new(cerebellum::computer_grants::AlwaysOpenRoute),
            drain,
            None,
        )
    };
    let read = serve_as(
        &plane,
        &management,
        identity(),
        consent(),
        "computer.read_state",
        json!({"target": target.bundle_identity}),
        InMemoryCaptureBackend::default(),
    )
    .await;
    let composer = id_of(read["state_text"].as_str().unwrap(), "Composer");
    for mode in ["replace_value", "insert_at_caret"] {
        let reply = serve_as(
            &plane,
            &management,
            identity(),
            consent(),
            "computer.write_text",
            json!({"element_id": composer, "text": SECRET, "write_mode": mode}),
            InMemoryCaptureBackend::default(),
        )
        .await;
        assert_eq!(reply["outcome"], "completed", "{reply}");
    }
    // Typed text too. This plane has no platform driver, so nothing is
    // posted, but the dispatcher journals the intent before it reaches the
    // driver, which is the record typed text could leak into.
    let before = plane.journal_entry_count().await;
    let typed = serve_as(
        &plane,
        &management,
        identity(),
        consent(),
        "computer.type",
        json!({"target": target.bundle_identity, "text": SECRET}),
        InMemoryCaptureBackend::default(),
    )
    .await;
    assert!(
        plane.journal_entry_count().await > before,
        "the type intent was not journaled, so its absence proves nothing: {typed}"
    );

    assert!(
        journal_contains(&storage, PLANTED),
        "the scan cannot find the planted marker in the journal, so it proves nothing"
    );
    assert!(
        !journal_contains(&storage, SECRET),
        "written or typed text reached the journal"
    );
}
