//! Representative synthetic trees, not captured application data. Menu tokens
//! deliberately churn while the window and sidebar retain their identities.
use super::*;
use crate::app_state::render::{render_change_report, render_diff, MAX_DIFF_BYTES};

fn menus(generation: u64, photoshop: bool) -> RawElement {
    let names: &[&str] = if photoshop {
        &[
            "Apple",
            "Photoshop",
            "File",
            "Edit",
            "Image",
            "Layer",
            "Type",
            "Select",
            "Filter",
            "View",
            "Window",
            "Help",
        ]
    } else {
        &["Apple", "Settings", "Window", "AutoFill"]
    };
    RawElement::fixture(900 + generation * 1000, "AXMenuBar").with_children(
        names
            .iter()
            .enumerate()
            .map(|(index, name)| {
                let base = 901 + generation * 1000 + index as u64 * 60;
                let count = if *name == "AutoFill" { 3 } else { 30 };
                RawElement::fixture(base, "AXMenuBarItem")
                    .titled(name)
                    .with_children(vec![RawElement::fixture(base + 1, "AXMenu").with_children(
                        (0..count)
                            .map(|n| {
                                RawElement::fixture(base + 2 + n, "AXMenuItem")
                                    .titled(&format!("Synthetic {name} command {n}"))
                            })
                            .collect(),
                    )])
            })
            .collect(),
    )
}

fn pane(generation: u64, photoshop: bool) -> RawAppState {
    let mut sidebar = RawElement::fixture(2, "AXOutline").titled("Sidebar");
    sidebar.subrole = Some("AXSidebar".into());
    sidebar.children = (0..20)
        .map(|n| RawElement::fixture(10 + n, "AXRow").titled(&format!("Navigation category {n}")))
        .collect();
    let base = 100_000 + generation * 100;
    let content = RawElement::fixture(base, "AXGroup")
        .titled(&format!("Privacy pane {generation}"))
        .with_children(
            (0..18)
                .map(|n| {
                    let role = if n % 3 == 0 {
                        "AXCheckBox"
                    } else if n % 3 == 1 {
                        "AXStaticText"
                    } else {
                        "AXButton"
                    };
                    RawElement::fixture(base + n + 1, role)
                        .titled(&format!("Pane {generation} control {n}"))
                })
                .collect(),
        );
    state(vec![
        menus(generation, photoshop),
        RawElement::fixture(1, "AXWindow")
            .titled(if photoshop {
                "Synthetic artwork"
            } else {
                "Settings"
            })
            .with_children(vec![sidebar, content]),
    ])
}

#[test]
fn closed_menu_items_never_leak_into_change_reports() {
    let sessions = AppStateSessions::with_run_tag("kq");
    read(&sessions, &pane(0, false));
    let after = read(&sessions, &pane(1, false));
    let diff = render_diff(&after.roots, &after.diff, None).text;
    assert!(!diff.contains("Synthetic Window command"), "{diff}");
    assert!(
        diff.contains("menu bar item Window  [30 children; closed]"),
        "{diff}"
    );
    let outline = rendered(&after, &StateRequest::default());
    assert!(!outline.contains("Synthetic Window command"));
    let zoom = rendered(
        &after,
        &StateRequest {
            zoom: Some(Zoom::MenuBar),
            ..Default::default()
        },
    );
    assert!(zoom.contains("Synthetic Window command 0"), "{zoom}");
}

#[test]
fn open_menu_items_expand_on_selection_or_visibility() {
    for visible in [false, true] {
        let mut raw = pane(0, false);
        let menu = &mut raw.roots[0].children[2];
        menu.selected = !visible;
        menu.children[0].menu_visible = visible;
        let observed = read(&AppStateSessions::with_run_tag("kq"), &raw);
        assert!(
            rendered(&observed, &StateRequest::default()).contains("Synthetic Window command 0")
        );
    }
}

#[test]
fn collapsed_menu_reads_preserve_ids_and_do_not_invent_removals() {
    let sessions = AppStateSessions::with_run_tag("kq");
    let full = pane(0, false);
    let before = read(&sessions, &full);
    let item = id_of(&before, "Synthetic Window command 0");
    let mut collapsed = full.clone();
    for title in &mut collapsed.roots[0].children {
        let menu = &mut title.children[0];
        menu.closed_menu_children = menu.children.len();
        menu.children.clear();
    }
    for _ in 0..5 {
        assert!(!sessions.differs_from_baseline(CONVERSATION, &grant(), &collapsed));
        let after = read(&sessions, &collapsed);
        assert_eq!(
            after.diff,
            StateDiff::default(),
            "collapse is a read choice, not an application change"
        );
    }
    assert!(matches!(
        sessions.resolve(CONVERSATION, &item),
        ElementResolution::Live { .. }
    ));
    let mut opened = full;
    opened.roots[0].children[2].selected = true;
    opened.roots[0].children[2].children[0].menu_visible = true;
    let after = read(&sessions, &opened);
    assert_eq!(id_of(&after, "Synthetic Window command 0"), item);
    assert!(!after.diff.added.contains(&item));
    let report = render_change_report(&HEADER, &after, &StateRequest::default());
    assert_eq!(report.kind, "filtered_state");
    assert!(report.text.starts_with("Opened menu:\n"));
    assert!(report.text.contains("Synthetic Window command 0"));
}

#[test]
fn unchanged_ids_are_not_added_when_a_parent_returns() {
    let sessions = AppStateSessions::with_run_tag("kq");
    let original = pane(0, false);
    let before = read(&sessions, &original);
    let unchanged = id_of(&before, "Pane 0 control 0");
    read(&sessions, &pane(1, false));
    let mut returned = original;
    returned.roots[1].handle = Arc::new(FixtureElementToken(800_000));
    let after = read(&sessions, &returned);
    assert_eq!(id_of(&after, "Pane 0 control 0"), unchanged);
    assert!(!after.diff.added.contains(&unchanged), "{:?}", after.diff);
    assert!(!after.diff.changed.contains(&unchanged));
    assert!(!render_diff(&after.roots, &after.diff, None)
        .text
        .contains("Pane 0 control 0"));
}

#[test]
fn a_whole_pane_navigation_returns_a_replacement_outline() {
    let sessions = AppStateSessions::with_run_tag("kq");
    read(&sessions, &pane(0, false));
    let after = read(&sessions, &pane(1, false));
    let report = render_change_report(&HEADER, &after, &StateRequest::default());
    assert_eq!(report.kind, "replacement");
    assert!(report.text.starts_with("State replaced:\n"));
    let outline = render_state(&HEADER, &after.roots, &StateRequest::default()).text;
    assert_eq!(report.text, format!("State replaced:\n{outline}"));
    assert!(report.text.find("Privacy pane 1").unwrap() < report.text.find("Sidebar").unwrap());
    assert!(report.text.find("Sidebar").unwrap() < report.text.find("menu bar").unwrap());
    assert!(report.text.len() <= MAX_DIFF_BYTES);
}

#[test]
fn action_filters_return_state_matches_not_just_changed_matches() {
    let sessions = AppStateSessions::with_run_tag("kq");
    let raw = pane(0, false);
    read(&sessions, &raw);
    let after = read(&sessions, &raw);
    let roles = vec!["CheckBox".into()];
    let report = render_change_report(
        &HEADER,
        &after,
        &StateRequest {
            roles: &roles,
            text: Some("control 0"),
            zoom: None,
        },
    );
    assert_eq!(report.kind, "filtered_state");
    assert!(report.text.contains("check box Pane 0 control 0"));
    assert!(!report.text.contains("control 1"));
}

#[test]
fn replacement_budget_cuts_chrome_after_main_content_and_discloses_it() {
    let sessions = AppStateSessions::with_run_tag("kq");
    read(&sessions, &pane(0, false));
    let mut raw = pane(1, false);
    raw.roots[1].children[0].children = (0..150)
        .map(|n| {
            RawElement::fixture(500_000 + n, "AXGroup")
                .titled(&format!(
                    "Sidebar section {}",
                    char::from_u32(0x4e00 + n as u32).unwrap()
                ))
                .with_children(vec![
                    RawElement::fixture(600_000 + n, "AXButton").titled("Navigate")
                ])
        })
        .collect();
    let after = read(&sessions, &raw);
    let report = render_change_report(&HEADER, &after, &StateRequest::default());
    assert!(report.text.contains("Privacy pane 1"), "{}", report.text);
    assert!(report
        .text
        .contains("cut (menus and sidebars after main content)"));
    assert!(report.truncation.is_some());
    assert!(report.text.len() <= MAX_DIFF_BYTES);
}

#[test]
fn representative_navigation_report_sizes() {
    for photoshop in [false, true] {
        let sessions = AppStateSessions::with_run_tag("kq");
        read(&sessions, &pane(0, photoshop));
        let mut bytes = Vec::new();
        for navigation in 1..=8 {
            let after = read(&sessions, &pane(navigation, photoshop));
            let report = render_change_report(&HEADER, &after, &StateRequest::default());
            bytes.push(report.text.len());
            assert_eq!(report.kind, "replacement");
            assert!(report.text.len() < MAX_DIFF_BYTES);
            assert!(report.truncation.is_none());
        }
        println!("{} navigation report bytes: {bytes:?}; fixture traversal calls: 16 (1 read + 8 pane presses + 7 back presses), no forced follow-up reads", if photoshop { "Photoshop-shaped" } else { "Settings-shaped" });
    }
}
