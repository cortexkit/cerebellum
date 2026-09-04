//! Session-ending synthetic key chords that this module never dispatches.

use super::synthetic::{SyntheticKey, SyntheticKeyModifiers};

/// The operating system on which a blocked chord ends this module's session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockedChordPlatform {
    MacOs,
    Windows,
}

/// A platform-specific chord that ends the session this module is running in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockedChord {
    pub platform: BlockedChordPlatform,
    /// Canonical wire spelling, also used to name this chord in tests and logs.
    pub chord: &'static [&'static str],
    pub modifiers: SyntheticKeyModifiers,
    pub key: SyntheticKey,
    pub reason: &'static str,
}

/// Chords that end the current session rather than act inside the target app.
///
/// Semantic clicks on menu items such as "Log Out…" and "Empty Trash" are not
/// covered here: their titles are localized, while the semantic path addresses
/// controls by role and title. A title list would be English-only coverage.
///
/// macOS eject and power keys are intentionally absent because `SyntheticKey`
/// has no neutral name for either key. Windows Ctrl+Alt+Delete is absent because
/// user-mode synthesis cannot deliver the secure-attention sequence.
pub const BLOCKED_CHORDS: &[BlockedChord] = &[
    // Ends the macOS session by locking the screen.
    BlockedChord {
        platform: BlockedChordPlatform::MacOs,
        chord: &["command", "control", "q"],
        modifiers: SyntheticKeyModifiers {
            command: true,
            control: true,
            ..SyntheticKeyModifiers::NONE
        },
        key: SyntheticKey::Q,
        reason: "lock",
    },
    // Ends the macOS session by logging the user out.
    BlockedChord {
        platform: BlockedChordPlatform::MacOs,
        chord: &["command", "shift", "q"],
        modifiers: SyntheticKeyModifiers {
            command: true,
            shift: true,
            ..SyntheticKeyModifiers::NONE
        },
        key: SyntheticKey::Q,
        reason: "logout",
    },
    // Ends the macOS session by opening the force-quit dialog.
    BlockedChord {
        platform: BlockedChordPlatform::MacOs,
        chord: &["command", "option", "escape"],
        modifiers: SyntheticKeyModifiers {
            command: true,
            option: true,
            ..SyntheticKeyModifiers::NONE
        },
        key: SyntheticKey::Escape,
        reason: "force_quit",
    },
    // Ends the macOS session by emptying the Trash.
    BlockedChord {
        platform: BlockedChordPlatform::MacOs,
        chord: &["command", "shift", "backspace"],
        modifiers: SyntheticKeyModifiers {
            command: true,
            shift: true,
            ..SyntheticKeyModifiers::NONE
        },
        key: SyntheticKey::Backspace,
        reason: "empty_trash",
    },
    // Ends the macOS session by force-quitting the frontmost app without a dialog.
    BlockedChord {
        platform: BlockedChordPlatform::MacOs,
        chord: &["command", "option", "shift", "escape"],
        modifiers: SyntheticKeyModifiers {
            command: true,
            option: true,
            shift: true,
            ..SyntheticKeyModifiers::NONE
        },
        key: SyntheticKey::Escape,
        reason: "force_quit",
    },
    // Ends the Windows session by locking the workstation.
    BlockedChord {
        platform: BlockedChordPlatform::Windows,
        chord: &["windows", "l"],
        modifiers: SyntheticKeyModifiers {
            windows: true,
            ..SyntheticKeyModifiers::NONE
        },
        key: SyntheticKey::L,
        reason: "lock",
    },
];

/// Return the session-ending chord that exactly matches this platform and input.
pub fn blocked_chord(
    modifiers: SyntheticKeyModifiers,
    key: SyntheticKey,
    platform: BlockedChordPlatform,
) -> Option<&'static BlockedChord> {
    BLOCKED_CHORDS.iter().find(|blocked| {
        blocked.platform == platform && blocked.modifiers == modifiers && blocked.key == key
    })
}

/// The platform that this build can dispatch synthetic input to.
pub const fn current_blocked_chord_platform() -> Option<BlockedChordPlatform> {
    #[cfg(target_os = "macos")]
    {
        Some(BlockedChordPlatform::MacOs)
    }
    #[cfg(target_os = "windows")]
    {
        Some(BlockedChordPlatform::Windows)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_listed_chord_is_found_only_on_its_platform() {
        for blocked in BLOCKED_CHORDS {
            assert_eq!(
                blocked_chord(blocked.modifiers, blocked.key, blocked.platform),
                Some(blocked),
                "{} chord is absent from the session floor",
                blocked.reason
            );
        }
    }

    #[test]
    fn exact_modifier_matching_leaves_normal_command_chords_grantable() {
        assert_eq!(
            blocked_chord(
                SyntheticKeyModifiers {
                    command: true,
                    ..SyntheticKeyModifiers::NONE
                },
                SyntheticKey::Q,
                BlockedChordPlatform::MacOs,
            ),
            None,
            "Command-Q quits only the target app, not this module's session"
        );
        assert_eq!(
            blocked_chord(
                SyntheticKeyModifiers {
                    command: true,
                    shift: true,
                    ..SyntheticKeyModifiers::NONE
                },
                SyntheticKey::S,
                BlockedChordPlatform::MacOs,
            ),
            None,
            "Command-Shift-S is not the logout chord"
        );
    }
}
