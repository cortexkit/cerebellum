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
        .with_permission_liveness(super::support::computer::live_permissions())
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

/// An element id's run tag and number: `kq105` is `("kq", 105)`.
fn split_id(id: &str) -> (&str, u64) {
    let (tag, number) = id.split_at(2);
    (
        tag,
        number
            .parse()
            .unwrap_or_else(|_| panic!("{id:?} is not an element id")),
    )
}

/// The ids an action reply's diff names as `added` (`+` lines), `changed`
/// (`~` lines) or `removed` (the ranges after `Removed element IDs:`).
fn ids(reply: &Value, field: &str) -> Vec<String> {
    let text = reply["state_text"]
        .as_str()
        .unwrap_or_else(|| panic!("the diff is missing from {reply}"));
    let first_word = |line: &str| line[1..].split_whitespace().next().unwrap().to_string();
    match field {
        "added" => text
            .lines()
            .filter(|line| line.starts_with('+'))
            .map(first_word)
            .collect(),
        "changed" => text
            .lines()
            .filter(|line| line.starts_with('~'))
            .map(first_word)
            .collect(),
        "removed" => text
            .lines()
            .filter_map(|line| line.strip_prefix("Removed element IDs: "))
            .flat_map(|ranges| ranges.split(", "))
            // A range writes its first id whole and its last as a number:
            // `kq7-9` is kq7, kq8 and kq9.
            .flat_map(|range| match range.split_once('-') {
                Some((first, end)) => {
                    let (tag, start) = split_id(first);
                    let end: u64 = end.parse().unwrap();
                    (start..=end)
                        .map(|number| format!("{tag}{number}"))
                        .collect::<Vec<_>>()
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

#[tokio::test]
async fn a_press_batch_stops_at_the_first_failed_press() {
    let desk = desk();
    desk.state().after_action = Some(after_send());
    let plane = plane(&desk);
    let management = granted_management().await;
    let tree = read(&plane, &management).await;
    let send = id_of(&tree, " button Send");
    let label = id_of(&tree, " text Hello");
    let journaled = plane.journal_entry_count().await;
    let reply = serve(
        &plane,
        &management,
        "computer.press_element",
        json!({"element_ids":[send, label, send]}),
    )
    .await;
    assert_eq!(reply["outcome"], "no_press_action", "{reply}");
    assert_eq!(reply["stopped_at"], 2);
    assert_eq!(reply["steps"].as_array().unwrap().len(), 2);
    assert_eq!(reply["steps"][0]["outcome"], "completed");
    assert_eq!(reply["steps"][1]["outcome"], "no_press_action");
    assert_eq!(
        desk.state().presses,
        [10],
        "the third press must never reach the source"
    );
    assert!(reply["state_text"].as_str().unwrap().contains(" text Sent"));
    assert!(
        !reply["state_text"].as_str().unwrap().contains("~"),
        "a parent's new child must not pretend its unchanged line changed: {reply}"
    );
    assert_eq!(
        plane.journal_entry_count().await - journaled,
        2,
        "each attempted press has its own journal row"
    );
}

#[tokio::test]
async fn four_disclosure_presses_share_one_report_and_keep_their_order() {
    let roots = vec![RawElement::fixture(1, "AXWindow")
        .titled("Automation")
        .with_children(
            (10..14)
                .map(|id| {
                    RawElement::fixture(id, "AXDisclosureTriangle")
                        .titled(&format!("Automation {id}"))
                })
                .collect(),
        )];
    let mut desk = Desk::new(roots);
    for id in 10..14 {
        desk = desk.with_element(
            id,
            DeskElement {
                facts: facts("AXDisclosureTriangle", &["AXPress"]),
                ..Default::default()
            },
        );
    }
    let plane = plane(&desk);
    let management = granted_management().await;
    let tree = serve(
        &plane,
        &management,
        "computer.read_state",
        json!({"target":TARGET_BUNDLE_ID, "role_filter":["AXDisclosureTriangle"]}),
    )
    .await["state_text"]
        .as_str()
        .unwrap()
        .to_owned();
    let ids: Vec<_> = (10..14)
        .map(|id| id_of(&tree, &format!("Automation {id}")))
        .collect();
    let journaled = plane.journal_entry_count().await;
    let reply = serve(
        &plane,
        &management,
        "computer.press_element",
        json!({"element_ids":ids}),
    )
    .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(desk.state().presses, [10, 11, 12, 13]);
    assert_eq!(reply["steps"].as_array().unwrap().len(), 4);
    assert!(reply.get("stopped_at").is_none());
    assert_eq!(plane.journal_entry_count().await - journaled, 4);
    assert_eq!(reply["state_report"], "diff");
    assert!(reply["state_text"]
        .as_str()
        .unwrap()
        .contains("No change seen"));
}

#[tokio::test]
async fn press_filters_return_the_new_panes_checkboxes_and_labels() {
    let desk = desk();
    let mut after = after_send();
    after[0]
        .children
        .push(RawElement::fixture(14, "AXCheckBox").titled("Full Disk Access"));
    desk.state().after_action = Some(after);
    let plane = plane(&desk);
    let management = granted_management().await;
    let tree = read(&plane, &management).await;
    let reply = serve(&plane, &management, "computer.press_element", json!({"element_id":id_of(&tree, " button Send"), "role_filter":["check box", "text"], "text_filter":"Access"})).await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(reply["state_report"], "filtered_state");
    let text = reply["state_text"].as_str().unwrap();
    assert!(text.contains("check box Full Disk Access"));
    assert!(!text.contains(" button Send"));
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
    // A read first, so the session exists and the ids below are refused for
    // what they are rather than for there being no session.
    let tree = read(&plane, &management).await;
    // An id in the salted shape ids had before, a bare number, and a number
    // this run never issued.
    let tag = &id_of(&tree, " button Send")[..2];
    for stale in [
        "sgone1-4".to_string(),
        "10".to_string(),
        format!("{tag}999999"),
    ] {
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
    let (tag, menu_number) = split_id(menu);
    assert_eq!(save, format!("{tag}{}", menu_number + 2), "{tree}");
    let log_out = format!("{tag}{}", menu_number + 1);
    assert!(
        !tree
            .lines()
            .any(|line| line.trim_start().starts_with(&format!("{log_out} ")))
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
/// system-wide hit would land in it. The element found sits in the window the
/// image shows (window 77, the one `capturing` captures), so it is pressed,
/// the pointer is not used, and the element is given an id the diff can name.
#[tokio::test]
async fn a_point_is_hit_tested_in_its_own_application_and_pressed() {
    let desk = desk();
    {
        let mut state = desk.state();
        state.application_hit = Some((60, Some(grant().pid)));
        state.element_windows.insert(60, 77);
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
        state.element_windows.insert(70, 77);
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

/// The application-scoped hit test finds the topmost element of the
/// application at the point in any of its windows. With a second window of
/// the same application over the imaged one there, the element found is in
/// that window, which the image does not show: nothing is pressed, the element
/// is not given an id, and the refusal names the application.
#[tokio::test]
async fn a_hit_in_another_window_of_the_same_application_presses_nothing() {
    let desk = desk();
    {
        let mut state = desk.state();
        state.application_hit = Some((60, Some(grant().pid)));
        state.element_windows.insert(60, 78);
        state.elements.insert(
            60,
            DeskElement {
                facts: facts("AXButton", &["AXPress"]),
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
        json!({"image_id": image_id, "x": 625, "y": 125}),
    )
    .await;
    assert_eq!(reply["outcome"], "point_in_another_window", "{reply}");
    assert!(
        reply["remedy"]
            .as_str()
            .is_some_and(|remedy| remedy.contains("element id")),
        "{reply}"
    );
    assert!(reply.get("state_text").is_none(), "{reply}");
    assert!(desk.state().presses.is_empty());
    assert!(plane.result_schema_findings().is_empty());
}

/// A hit element whose window cannot be established is not taken to be in
/// the imaged window: nothing is pressed.
#[tokio::test]
async fn a_hit_whose_window_cannot_be_established_presses_nothing() {
    let desk = desk();
    {
        let mut state = desk.state();
        state.application_hit = Some((60, Some(grant().pid)));
        state.elements.insert(
            60,
            DeskElement {
                facts: facts("AXButton", &["AXPress"]),
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
        json!({"image_id": image_id, "x": 625, "y": 125}),
    )
    .await;
    assert_eq!(reply["outcome"], "point_in_another_window", "{reply}");
    assert!(desk.state().presses.is_empty());
    assert!(plane.result_schema_findings().is_empty());
}

/// An image registered without the window it shows ties its pixels to no
/// window, so no hit can be confirmed to lie in it: even an element that sits
/// in a window of the application is not pressed.
#[tokio::test]
async fn a_point_of_an_image_registered_without_its_window_presses_nothing() {
    use cerebellum_computer::app_state::{image::ImageMapping, session::RegisteredImage};
    let desk = desk();
    {
        let mut state = desk.state();
        state.application_hit = Some((60, Some(grant().pid)));
        state.element_windows.insert(60, 77);
        state.elements.insert(
            60,
            DeskElement {
                facts: facts("AXButton", &["AXPress"]),
                ..DeskElement::default()
            },
        );
    }
    let plane = plane(&desk);
    let management = granted_management().await;
    // A read with an image first, so the conversation has seen the
    // application; the image acted on is a second one with no window.
    read_with_image(&plane, &management).await;
    let image_id = management.app_state_sessions().register_image(
        &identity().conversation_key,
        RegisteredImage {
            bundle_identity: grant().bundle_identity,
            pid: grant().pid,
            process_generation: grant().process_generation_evidence,
            width_px: 1000,
            height_px: 600,
            mapping: ImageMapping::for_window(
                (100.0, 50.0),
                (1000.0, 600.0),
                (1000, 600),
                (1000, 600),
            )
            .expect("a whole-window mapping"),
        },
    );
    let reply = serve(
        &plane,
        &management,
        "computer.press_point",
        json!({"image_id": image_id, "x": 500, "y": 100}),
    )
    .await;
    assert_eq!(reply["outcome"], "point_in_another_window", "{reply}");
    assert!(desk.state().presses.is_empty());
    assert!(plane.result_schema_findings().is_empty());
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
    .with_permission_liveness(super::support::computer::live_permissions())
    .with_app_state_source(desk().source());
    let carrier = ScriptedCarrier::answering(&["allow_30m"]);
    let consent = || {
        let (drain_sender, drain) = tokio::sync::watch::channel(false);
        std::mem::forget(drain_sender);
        ConsentContext::new(
            GrantCaller::new(identity().conversation_key, GRANTEE.into(), false),
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

/// An id carrying another run's tag is refused even when this run issued its
/// number to a live element: after a restart that number names a different
/// element, so pressing or writing it would act on the wrong one. Nothing is
/// pressed or written, and the reply says to read again.
#[tokio::test]
async fn an_id_from_before_a_restart_refuses_even_when_its_number_is_live() {
    let desk = desk();
    let plane = plane(&desk);
    let management = granted_management().await;
    let tree = read(&plane, &management).await;
    let send = id_of(&tree, " button Send");
    let composer = id_of(&tree, "Composer");
    let (tag, number) = split_id(&send);
    // Any other two letters of the tag alphabet stand for an earlier run.
    let earlier = if tag == "ab" { "cd" } else { "ab" };
    let (_, composer_number) = split_id(&composer);

    let pressed = serve(
        &plane,
        &management,
        "computer.press_element",
        json!({"element_id": format!("{earlier}{number}")}),
    )
    .await;
    let written = serve(
        &plane,
        &management,
        "computer.write_text",
        json!({"element_id": format!("{earlier}{composer_number}"), "text": "x", "write_mode": "replace_value"}),
    )
    .await;
    for reply in [&pressed, &written] {
        assert_eq!(reply["outcome"], "stale_element", "{reply}");
        assert_eq!(
            reply["remedy"],
            "read_state again; ids from before a restart no longer apply"
        );
    }
    assert!(desk.state().presses.is_empty() && desk.state().writes.is_empty());

    // The same numbers under this run's tag are live and act.
    let live = serve(
        &plane,
        &management,
        "computer.press_element",
        json!({"element_id": send}),
    )
    .await;
    assert_eq!(live["outcome"], "completed", "{live}");
    assert_eq!(desk.state().presses, vec![10]);
    assert!(plane.result_schema_findings().is_empty());
}

// ---------------------------------------------------------------------------
// Applications by name, and list_apps
// ---------------------------------------------------------------------------

fn running(
    name: &str,
    bundle_identity: &str,
    pid: u32,
) -> cerebellum_computer::app_state::source::RunningApp {
    cerebellum_computer::app_state::source::RunningApp {
        name: name.into(),
        bundle_identity: bundle_identity.into(),
        pid,
        frontmost: false,
    }
}

/// A target given as a name: one running match is read, several are refused
/// as `ambiguous_app` with the candidates, none as `no_running_app_named`;
/// a bundle identity nobody runs is still `not_running`. Every reply passes
/// its row's result schema in withholding mode.
#[tokio::test]
async fn a_target_name_resolves_to_exactly_one_running_application() {
    let desk = desk();
    desk.state().running = Some(vec![
        running("Safari", TARGET_BUNDLE_ID, grant().pid),
        running("Editor", "com.example.Editor", 501),
        running("Editor", "org.example.Editor", 502),
    ]);
    let plane = plane(&desk);
    let management = granted_management().await;

    let one = serve(
        &plane,
        &management,
        "computer.read_state",
        json!({"target": "safari"}),
    )
    .await;
    assert_eq!(one["outcome"], "completed", "{one}");
    assert!(
        one["state_text"].as_str().unwrap().contains(" button Send"),
        "{one}"
    );

    let several = serve(
        &plane,
        &management,
        "computer.read_state",
        json!({"target": "Editor"}),
    )
    .await;
    assert_eq!(several["outcome"], "ambiguous_app", "{several}");
    let candidates: Vec<&str> = several["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|candidate| candidate["bundle_identity"].as_str().unwrap())
        .collect();
    assert_eq!(candidates, vec!["com.example.Editor", "org.example.Editor"]);

    let none = serve(
        &plane,
        &management,
        "computer.type",
        json!({"target": "Nobody", "text": "x"}),
    )
    .await;
    assert_eq!(none["outcome"], "no_running_app_named", "{none}");
    assert_eq!(none["target"], "Nobody");

    let missing = support::computer::management_with(Arc::new(support::computer::Fixed(
        TargetResolution::NotRunning,
    )));
    let not_running = serve(
        &plane,
        &missing,
        "computer.read_state",
        json!({"target": "com.example.NotInstalled"}),
    )
    .await;
    assert_eq!(not_running["outcome"], "not_running", "{not_running}");
    assert!(plane.result_schema_findings().is_empty());
}

/// An element action's `target` is checked against the element's own
/// application: one naming another application is refused and nothing is
/// pressed or written; one naming the element's application by name or
/// bundle identity changes nothing.
#[tokio::test]
async fn an_element_action_refuses_a_target_naming_another_application() {
    let desk = desk();
    desk.state().running = Some(vec![
        running("Safari", TARGET_BUNDLE_ID, grant().pid),
        running("Notes", "com.apple.Notes", 777),
    ]);
    let plane = plane(&desk);
    let management = granted_management().await;
    let tree = read(&plane, &management).await;
    let send = id_of(&tree, " button Send");
    let composer = id_of(&tree, "Composer");

    for other in ["com.apple.Notes", "Notes"] {
        let pressed = serve(
            &plane,
            &management,
            "computer.press_element",
            json!({"element_id": send, "target": other}),
        )
        .await;
        assert_eq!(pressed["outcome"], "target_mismatch", "{pressed}");
        let written = serve(
            &plane,
            &management,
            "computer.write_text",
            json!({"element_id": composer, "target": other, "text": "x", "write_mode": "replace_value"}),
        )
        .await;
        assert_eq!(written["outcome"], "target_mismatch", "{written}");
    }
    assert!(desk.state().presses.is_empty() && desk.state().writes.is_empty());

    for own in ["Safari", TARGET_BUNDLE_ID] {
        let pressed = serve(
            &plane,
            &management,
            "computer.press_element",
            json!({"element_id": send, "target": own}),
        )
        .await;
        assert_eq!(pressed["outcome"], "completed", "{own}: {pressed}");
    }
    assert_eq!(desk.state().presses, vec![10, 10]);
    assert!(plane.result_schema_findings().is_empty());
}

/// list_apps is served in withholding mode without any application's grant:
/// one line per running application, the frontmost marked. Its journal row
/// holds the count alone. The scan that finds no application name is first
/// shown to find a planted marker the journal does record, the bundle
/// identity of the application a read was granted for, so its silence
/// about the names means something.
#[tokio::test]
async fn list_apps_is_served_without_a_grant_and_journals_only_the_count() {
    const PLANTED: &str = "PlantedPositive9d2c";
    const SECRET_NAME: &str = "Sw0rdf1sh Private Ledger";
    const SECRET_BUNDLE: &str = "com.example.LedgerSecret4e1b";
    let target = ProcessGrant {
        bundle_identity: format!("com.example.{PLANTED}"),
        ..grant()
    };
    let desk = desk();
    desk.state().running = Some(vec![
        running("Safari", &target.bundle_identity, grant().pid),
        running(SECRET_NAME, SECRET_BUNDLE, 4321),
    ]);
    if let Some(apps) = desk.state().running.as_mut() {
        apps[0].frontmost = true;
    }
    let storage = InMemoryJournalStorage::new();
    let plane: Plane = ComputerPlane::with_result_schema_enforcement(
        support::computer::audit_with_storage(storage.clone()),
        ResultSchemaEnforcement::Withhold,
    )
    .with_permission_liveness(super::support::computer::live_permissions())
    .with_app_state_source(desk.source());
    let management = support::computer::management_with(Arc::new(support::computer::Fixed(
        TargetResolution::Resolved(target.clone()),
    )));

    // No grant is held and no question can be asked: the list needs neither.
    let before = plane.journal_entry_count().await;
    let listed = serve(&plane, &management, "computer.list_apps", json!({})).await;
    assert_eq!(listed["outcome"], "completed", "{listed}");
    assert_eq!(
        listed["state_text"],
        format!(
            "Safari · {} · pid {} · frontmost\n{SECRET_NAME} · {SECRET_BUNDLE} · pid 4321\ninstalled (not running):\n",
            target.bundle_identity,
            grant().pid
        )
    );
    assert_eq!(listed["apps"].as_array().unwrap().len(), 2);
    assert!(
        plane.journal_entry_count().await > before,
        "the listing was not journaled, so its absence of names proves nothing"
    );

    // A granted read journals the bundle identity it was granted for.
    let carrier = ScriptedCarrier::answering(&["allow_30m"]);
    let (drain_sender, drain) = tokio::sync::watch::channel(false);
    std::mem::forget(drain_sender);
    let consent = ConsentContext::new(
        GrantCaller::new(identity().conversation_key, GRANTEE.into(), false),
        Some(Arc::new(carrier) as Arc<dyn QuestionCarrier>),
        Arc::new(cerebellum::computer_grants::AlwaysOpenRoute),
        drain,
        None,
    );
    let read = serve_as(
        &plane,
        &management,
        identity(),
        consent,
        "computer.read_state",
        json!({"target": target.bundle_identity}),
        InMemoryCaptureBackend::default(),
    )
    .await;
    assert_eq!(read["outcome"], "completed", "{read}");

    assert!(
        journal_contains(&storage, PLANTED),
        "the scan cannot find the planted marker in the journal, so it proves nothing"
    );
    assert!(
        journal_contains(&storage, "app_count"),
        "the count was not recorded"
    );
    for secret in [SECRET_NAME, SECRET_BUNDLE, "Sw0rdf1sh"] {
        assert!(
            !journal_contains(&storage, secret),
            "{secret} reached the journal"
        );
    }

    // An unreadable list is disclosed, never shown as no applications.
    desk.state().running = None;
    let unreadable = serve(&plane, &management, "computer.list_apps", json!({})).await;
    assert_eq!(unreadable["outcome"], "targets_unreadable", "{unreadable}");
    let invalid = serve(
        &plane,
        &management,
        "computer.list_apps",
        json!({"target": "Safari"}),
    )
    .await;
    assert_eq!(invalid["outcome"], "invalid_request", "{invalid}");
    assert!(plane.result_schema_findings().is_empty());
}

/// The cursor transport is the helper's pipe double. A dropped receiver models
/// its death without ever starting AppKit on the desk running the gate.
#[tokio::test]
async fn cursor_every_action_reply_is_byte_identical_on_off_and_dead_transport() {
    use cerebellum::computer_capability::cursor::Coordinator;
    let management = granted_management().await;
    let actions = [
        "computer.press_element",
        "computer.press_point",
        "computer.write_text",
        "computer.type",
        "computer.keys",
        "computer.read_state",
        "computer.wait",
        "computer.list_apps",
        "computer.takeover_move",
        "computer.takeover_drag",
        "computer.takeover_scroll",
    ];
    for action in actions {
        let mut replies = Vec::new();
        for mode in 0..3 {
            let desk = desk();
            desk.state().cursor_frame = Some([100.0, 60.0, 80.0, 20.0]);
            desk.state().cursor_visible = true;
            desk.state().focus = support::computer::DeskFocus::Element(12);
            desk.state().application_hit = Some((10, Some(grant().pid)));
            desk.state().element_windows.insert(10, 77);
            let base = plane(&desk);
            let state = serve(
                &base,
                &management,
                "computer.read_state",
                json!({"target": TARGET_BUNDLE_ID}),
            )
            .await;
            let button = id_of(state["state_text"].as_str().unwrap(), "Send");
            let field = id_of(state["state_text"].as_str().unwrap(), "Composer");
            let image = read_with_image(&base, &management).await;
            let args = match action {
                "computer.press_element" => json!({"element_id":button}),
                "computer.press_point" => json!({"image_id":image,"x":10,"y":10}),
                "computer.write_text" => {
                    json!({"element_id":field,"text":"hello world","write_mode":"replace_value"})
                }
                "computer.type" => json!({"target":TARGET_BUNDLE_ID,"text":"planted typed secret"}),
                "computer.keys" => json!({"target":TARGET_BUNDLE_ID,"keys":["return"]}),
                "computer.read_state" => json!({"target":TARGET_BUNDLE_ID}),
                "computer.wait" => {
                    json!({"app":TARGET_BUNDLE_ID,"predicate":cerebellum_computer::dispatch::post_condition::PostCondition::ElementEnabledIs { element: cerebellum_computer::platform::AccessibilityElementName::role_and_title("AXButton", "Save"), expected: true },"timeout_ms":0})
                }
                "computer.list_apps" => json!({}),
                "computer.takeover_move" => json!({"image_id":image,"to":{"x":10,"y":10}}),
                "computer.takeover_drag" => {
                    json!({"image_id":image,"from":{"x":10,"y":10},"to":{"x":20,"y":20}})
                }
                _ => json!({"target":TARGET_BUNDLE_ID,"axis":"vertical","amount_lines":1}),
            };
            let (cursor, mut receiver) = Coordinator::channel();
            let plane = if mode == 0 {
                base
            } else {
                base.with_cursor(cursor.clone())
            };
            let has_picture = matches!(
                action,
                "computer.press_element"
                    | "computer.press_point"
                    | "computer.write_text"
                    | "computer.type"
                    | "computer.keys"
                    | "computer.read_state"
            ) || (action == "computer.wait"
                && cfg!(any(target_os = "macos", target_os = "windows")));
            let call = serve(&plane, &management, action, args);
            let reply = if mode == 2 && has_picture {
                let (reply, killed) = tokio::join!(call, async {
                    let event =
                        tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv())
                            .await
                            .unwrap_or_else(|e| panic!("{action} mode {mode} no picture: {e}"))
                            .unwrap();
                    assert!(!serde_json::to_string(&event)
                        .unwrap()
                        .contains("planted typed secret"));
                    cursor.shutdown();
                    drop(receiver);
                });
                let () = killed;
                reply
            } else {
                if mode == 2 {
                    cursor.shutdown();
                }
                let reply = call.await;
                if mode == 1 && has_picture {
                    let event =
                        tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv())
                            .await
                            .unwrap_or_else(|e| panic!("{action} mode {mode} no picture: {e}"))
                            .unwrap();
                    assert!(!serde_json::to_string(&event)
                        .unwrap()
                        .contains("planted typed secret"));
                }
                reply
            };
            replies.push(serde_json::to_vec(&reply).unwrap());
        }
        assert_eq!(replies[0], replies[1], "{action}: cursor changed the reply");
        assert_eq!(
            replies[0], replies[2],
            "{action}: dead helper changed the reply"
        );
    }
}

#[tokio::test]
async fn cursor_planted_label_reaches_pipe_but_not_journal_or_call_records() {
    use cerebellum::computer_capability::cursor::Coordinator;
    use cerebellum::journal::call_records::{
        Begin, CallRecords, DispatchEvidence, InMemoryCallRecordStorage, Settlement,
    };
    const PLANT: &str = "CURSOR_PRIVATE";
    let desk = desk();
    desk.state().cursor_visible = true;
    desk.state().cursor_frame = Some([100.0, 60.0, 80.0, 20.0]);
    desk.state().elements.get_mut(&10).unwrap().facts.title = Some(PLANT.into());
    let storage = InMemoryJournalStorage::new();
    let base: Plane = ComputerPlane::new(support::computer::audit_with_storage(storage.clone()))
        .with_permission_liveness(support::computer::live_permissions())
        .with_app_state_source(desk.source());
    let management = granted_management().await;
    let read = serve(
        &base,
        &management,
        "computer.read_state",
        json!({"target":TARGET_BUNDLE_ID}),
    )
    .await;
    let button = id_of(read["state_text"].as_str().unwrap(), "Send");
    let (cursor, mut receiver) = Coordinator::channel();
    let plane = base.with_cursor(cursor);
    let records = InMemoryCallRecordStorage::new();
    let calls = CallRecords::open(Box::new(records.clone()), 0);
    let Begin::Execute(ticket) = calls.begin("direct", "cursor-test", "conversation", 1) else {
        panic!("fresh call must execute")
    };
    let reply = serve(
        &plane,
        &management,
        "computer.press_element",
        json!({"element_id":button}),
    )
    .await;
    let event = tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv())
        .await
        .unwrap()
        .unwrap()
        .picture()
        .expect("a picture line, not a hide");
    assert!(
        event.label.unwrap().contains("CURSOR_PRIVATE"),
        "the planted label must reach the actual pipe double"
    );
    let frame = subc_protocol::Frame::build_with_version(
        subc_protocol::PROTOCOL_VERSION,
        subc_protocol::FrameType::Response,
        subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
        1,
        1,
        7,
        serde_json::to_vec(&reply).unwrap(),
    )
    .unwrap();
    calls.settle(
        ticket,
        Settlement::from_reply(
            &frame,
            DispatchEvidence {
                committed: true,
                ..Default::default()
            },
        ),
        2,
    );
    assert!(!format!("{:?}", storage.load().unwrap()).contains(PLANT));
    let recorded = String::from_utf8(records.contents().unwrap()).unwrap();
    assert!(
        recorded.contains("cursor-test"),
        "the call records must actually have been written"
    );
    assert!(!recorded.contains(PLANT));
    assert!(!serde_json::to_string(&reply).unwrap().contains(PLANT));
}
