use super::*;

/// The production entry is the one place a computer plane starts reading
/// the person's config file; before that step the same planes read none.
#[test]
fn module_startup_points_the_computer_plane_at_the_config_file() {
    let expected = cerebellum_core::config::config_path();
    assert!(expected.is_some(), "this host has a config home");
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::default()),
        None,
        JournalPersistence::Isolated,
    );
    let computer = planes.computer.as_ref().unwrap().clone();
    assert_eq!(computer.app_use_config_path_for_test(), None);
    read_live_settings_from_config_file(&mut planes);
    assert_eq!(computer.app_use_config_path_for_test(), expected);
}
