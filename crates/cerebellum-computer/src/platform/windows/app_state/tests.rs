use super::*;
use crate::app_state::render::is_session_ending_title_for;

#[test]
fn native_client_initializes_on_a_windowless_mta() {
    assert!(WindowsAppStateSource::client_available());
}

#[test]
fn maps_ax_roles_without_promoting_document_to_web_area() {
    use super::uia::role;
    for (control, expected) in [
        (50000, "AXButton"),
        (50002, "AXCheckBox"),
        (50003, "AXComboBox"),
        (50004, "AXTextField"),
        (50009, "AXMenu"),
        (50010, "AXMenuBar"),
        (50011, "AXMenuItem"),
        (50013, "AXRadioButton"),
        (50030, "AXTextArea"),
        (50032, "AXWindow"),
        (50026, "uia_control_type:50026"),
    ] {
        assert_eq!(role(control, false, false, false), expected);
    }
    assert_eq!(role(50011, false, false, true), "AXMenuBarItem");
    assert_eq!(role(50026, false, true, false), "AXWindow");
    assert_eq!(role(50004, true, false, false), "AXSecureTextField");
}

#[test]
fn windows_menu_titles_do_not_change_the_shared_title_floor() {
    for title in ["Sign out", "Lock", "Switch user", "Hibernate", "Disconnect"] {
        assert!(is_session_ending_title_for(title, true), "{title}");
        assert!(!is_session_ending_title_for(title, false), "{title}");
    }
    assert!(is_session_ending_title_for(" Loc\u{212A}...  ", true));
    assert!(is_session_ending_title_for("  LOCK...  ", true));
    assert!(!is_session_ending_title_for("Lock formatting", true));
    assert!(is_session_ending_title_for("Lock Screen", false));
}

#[test]
fn windows_shared_defaults_expose_no_input_or_installed_state() {
    let source = WindowsAppStateSource::new(|_| false);
    let target = ProcessGrant {
        pid: 1,
        bundle_identity: "fixture".into(),
        process_generation_evidence: "1".into(),
    };
    assert!(source.time_since_last_input().is_none());
    assert!(matches!(
        source.hardware_input(&target),
        Err(ElementActionError::UnsupportedOnPlatform)
    ));
    assert!(source.cursor_window(&target, None).is_none());
    let installed = source.installed_apps(Duration::from_secs(2));
    assert!(!installed.complete);
    assert!(installed.apps.is_empty());
}
