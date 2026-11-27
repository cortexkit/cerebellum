#![cfg(target_os = "windows")]
#![forbid(unsafe_code)]

use cerebellum_computer::platform::WindowsElevation;
use cerebellum_windows::{
    current_process_token_elevation_type, current_session_provenance, SessionProvenance,
    TokenElevationType,
};

// Run explicitly with the Windows actuation nextest profile and `--run-ignored
// only`. Ordinary Windows unit-test jobs need not own the interactive console.
#[test]
#[ignore = "requires the dedicated native Windows actuation runner"]
fn runner_has_interactive_console_and_split_token_medium_integrity() {
    let session = current_session_provenance();
    assert!(
        matches!(session, SessionProvenance::Console { session_id } if session_id != 0),
        "native Windows actuation requires a nonzero interactive console session, got {session:?}"
    );
    let token_type = current_process_token_elevation_type();
    assert_eq!(
        token_type,
        Some(TokenElevationType::Limited),
        "native Windows actuation requires the filtered half of a UAC-enabled administrator split token"
    );
    assert_eq!(
        WindowsElevation::read_current_process(),
        WindowsElevation::Medium,
        "native Windows actuation requires a readable non-elevated medium-integrity primary token"
    );
}
