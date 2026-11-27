//! Session-ending synthetic key chords that this module never dispatches.

use super::synthetic::{SyntheticKey, SyntheticKeyModifiers};

/// The operating system on which a blocked chord ends this module's session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockedChordPlatform {
    MacOs,
    Windows,
    Linux,
}

/// Linux keysyms used by the blocked chords but absent from the wire key list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxFloorKeysym {
    SysRq,
    PowerOff,
    Sleep,
    Suspend,
    Hibernate,
    LogOff,
    ScreenSaver,
}

/// A key or key sequence that can end the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockedKey {
    Synthetic(SyntheticKey),
    LinuxKeysym(LinuxFloorKeysym),
    LinuxSuperTap,
    LinuxSysRqWithAnyKey,
}

/// A platform-specific chord that ends the session this module is running in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockedChord {
    pub platform: BlockedChordPlatform,
    /// Canonical wire spelling when expressible there; otherwise a name for logs.
    pub chord: &'static [&'static str],
    pub modifiers: SyntheticKeyModifiers,
    pub key: BlockedKey,
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
        key: BlockedKey::Synthetic(SyntheticKey::Q),
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
        key: BlockedKey::Synthetic(SyntheticKey::Q),
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
        key: BlockedKey::Synthetic(SyntheticKey::Escape),
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
        key: BlockedKey::Synthetic(SyntheticKey::Backspace),
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
        key: BlockedKey::Synthetic(SyntheticKey::Escape),
        reason: "force_quit",
    },
    // Ends the macOS session by logging the user out at once, without the
    // confirmation dialog that Shift-Command-Q shows.
    BlockedChord {
        platform: BlockedChordPlatform::MacOs,
        chord: &["command", "option", "shift", "q"],
        modifiers: SyntheticKeyModifiers {
            command: true,
            option: true,
            shift: true,
            ..SyntheticKeyModifiers::NONE
        },
        key: BlockedKey::Synthetic(SyntheticKey::Q),
        reason: "logout",
    },
    // Empties the Trash in Finder without asking for confirmation.
    BlockedChord {
        platform: BlockedChordPlatform::MacOs,
        chord: &["command", "option", "shift", "backspace"],
        modifiers: SyntheticKeyModifiers {
            command: true,
            option: true,
            shift: true,
            ..SyntheticKeyModifiers::NONE
        },
        key: BlockedKey::Synthetic(SyntheticKey::Backspace),
        reason: "empty_trash",
    },
    // Ends the Windows session by locking the workstation.
    BlockedChord {
        platform: BlockedChordPlatform::Windows,
        chord: &["windows", "l"],
        modifiers: SyntheticKeyModifiers {
            windows: true,
            ..SyntheticKeyModifiers::NONE
        },
        key: BlockedKey::Synthetic(SyntheticKey::L),
        reason: "lock",
    },
    linux_chord(
        &["option", "sysrq", "any"],
        modifiers(false, false, true, false),
        BlockedKey::LinuxSysRqWithAnyKey,
        "sysrq",
    ),
    linux_chord(
        &["command", "l"],
        modifiers(true, false, false, false),
        BlockedKey::Synthetic(SyntheticKey::L),
        "lock",
    ),
    linux_ctrl_alt(&["control", "option", "l"], SyntheticKey::L, "lock"),
    linux_ctrl_alt(
        &["control", "option", "forward_delete"],
        SyntheticKey::ForwardDelete,
        "logout",
    ),
    linux_ctrl_alt(
        &["control", "option", "backspace"],
        SyntheticKey::Backspace,
        "logout",
    ),
    linux_ctrl_alt(&["control", "option", "f1"], SyntheticKey::F1, "vt_switch"),
    linux_ctrl_alt(&["control", "option", "f2"], SyntheticKey::F2, "vt_switch"),
    linux_ctrl_alt(&["control", "option", "f3"], SyntheticKey::F3, "vt_switch"),
    linux_ctrl_alt(&["control", "option", "f4"], SyntheticKey::F4, "vt_switch"),
    linux_ctrl_alt(&["control", "option", "f5"], SyntheticKey::F5, "vt_switch"),
    linux_ctrl_alt(&["control", "option", "f6"], SyntheticKey::F6, "vt_switch"),
    linux_ctrl_alt(&["control", "option", "f7"], SyntheticKey::F7, "vt_switch"),
    linux_ctrl_alt(&["control", "option", "f8"], SyntheticKey::F8, "vt_switch"),
    linux_ctrl_alt(&["control", "option", "f9"], SyntheticKey::F9, "vt_switch"),
    linux_ctrl_alt(
        &["control", "option", "f10"],
        SyntheticKey::F10,
        "vt_switch",
    ),
    linux_ctrl_alt(
        &["control", "option", "f11"],
        SyntheticKey::F11,
        "vt_switch",
    ),
    linux_ctrl_alt(
        &["control", "option", "f12"],
        SyntheticKey::F12,
        "vt_switch",
    ),
    linux_keysym(&["XF86PowerOff"], LinuxFloorKeysym::PowerOff, "power"),
    linux_keysym(&["XF86Sleep"], LinuxFloorKeysym::Sleep, "power"),
    linux_keysym(&["XF86Suspend"], LinuxFloorKeysym::Suspend, "power"),
    linux_keysym(&["XF86Hibernate"], LinuxFloorKeysym::Hibernate, "power"),
    linux_keysym(&["XF86LogOff"], LinuxFloorKeysym::LogOff, "logout"),
    linux_keysym(&["XF86ScreenSaver"], LinuxFloorKeysym::ScreenSaver, "lock"),
    linux_chord(
        &["command"],
        modifiers(true, false, false, false),
        BlockedKey::LinuxSuperTap,
        "lock",
    ),
];

const fn linux_chord(
    chord: &'static [&'static str],
    modifiers: SyntheticKeyModifiers,
    key: BlockedKey,
    reason: &'static str,
) -> BlockedChord {
    BlockedChord {
        platform: BlockedChordPlatform::Linux,
        chord,
        modifiers,
        key,
        reason,
    }
}

const fn linux_ctrl_alt(
    chord: &'static [&'static str],
    key: SyntheticKey,
    reason: &'static str,
) -> BlockedChord {
    linux_chord(
        chord,
        modifiers(false, true, true, false),
        BlockedKey::Synthetic(key),
        reason,
    )
}

const fn linux_keysym(
    chord: &'static [&'static str],
    key: LinuxFloorKeysym,
    reason: &'static str,
) -> BlockedChord {
    linux_chord(
        chord,
        SyntheticKeyModifiers::NONE,
        BlockedKey::LinuxKeysym(key),
        reason,
    )
}

/// Return the session-ending chord that exactly matches a synthetic key and modifiers.
/// Linux delivery must use [`linux_blocked_chord`] to check keysyms and held keys too.
pub fn blocked_chord(
    modifiers: SyntheticKeyModifiers,
    key: SyntheticKey,
    platform: BlockedChordPlatform,
) -> Option<&'static BlockedChord> {
    BLOCKED_CHORDS.iter().find(|blocked| {
        blocked.platform == platform
            && blocked.modifiers == modifiers
            && blocked.key == BlockedKey::Synthetic(key)
    })
}

/// The key the Linux planner resolved, not the name in the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxResolvedKey {
    Synthetic(SyntheticKey),
    Keysym(LinuxFloorKeysym),
    /// A positively identified key outside the floor, such as a printable
    /// non-Latin character. An unresolved or ambiguous key is not `Other`.
    Other,
}

/// The input the Linux planner has verified it is about to post.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxChordInput {
    Key {
        /// Effective modifiers at the post, including those the person holds.
        modifiers: SyntheticKeyModifiers,
        key: LinuxResolvedKey,
        sysrq_held: bool,
    },
    /// A Super press and release with no other key in the chord.
    SuperTap,
}

/// The planner could not establish the key or effective modifier state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxChordUnreadable;

/// Check a resolved Linux input against the blocked session-ending chords.
/// If the planner cannot construct the input with certainty, `None` refuses
/// instead of being treated as an unlisted chord. Only `Ok(None)` passes this check.
pub fn linux_blocked_chord(
    input: Option<LinuxChordInput>,
) -> Result<Option<&'static BlockedChord>, LinuxChordUnreadable> {
    let input = input.ok_or(LinuxChordUnreadable)?;
    Ok(BLOCKED_CHORDS.iter().find(|blocked| {
        blocked.platform == BlockedChordPlatform::Linux
            && match (blocked.key, input) {
                (BlockedKey::LinuxSuperTap, LinuxChordInput::SuperTap) => true,
                (
                    BlockedKey::LinuxSysRqWithAnyKey,
                    LinuxChordInput::Key {
                        modifiers,
                        key,
                        sysrq_held,
                    },
                ) => {
                    // Stop the initial trigger as well as any continuation
                    // after the person has already pressed Alt and SysRq.
                    modifiers.option
                        && (sysrq_held || key == LinuxResolvedKey::Keysym(LinuxFloorKeysym::SysRq))
                }
                (
                    BlockedKey::LinuxKeysym(blocked_key),
                    LinuxChordInput::Key {
                        key: LinuxResolvedKey::Keysym(key),
                        ..
                    },
                ) => blocked_key == key,
                (
                    BlockedKey::Synthetic(blocked_key),
                    LinuxChordInput::Key {
                        modifiers,
                        key: LinuxResolvedKey::Synthetic(key),
                        ..
                    },
                ) => blocked_key == key && blocked.modifiers == modifiers,
                _ => false,
            }
    }))
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

/// A chord the operating system itself acts on, outside whichever
/// application receives it: Spotlight, the application switcher, Mission
/// Control, Spaces, screenshots, the input-source switch, the Dock and the
/// like.
///
/// An app grant covers what is done inside the granted application, so a
/// chord such as Command-Q or Command-W, which acts only on that application,
/// stays under it. A chord in this list reaches past the application, so the
/// app grant does not cover it and it needs the takeover grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemWideChord {
    pub platform: BlockedChordPlatform,
    /// Canonical wire spelling: modifiers in the order command, control,
    /// option, shift, then the key.
    pub chord: &'static [&'static str],
    pub modifiers: SyntheticKeyModifiers,
    pub key: SyntheticKey,
    /// What the system does on this chord, in the words of its source.
    pub action: &'static str,
}

const fn modifiers(
    command: bool,
    control: bool,
    option: bool,
    shift: bool,
) -> SyntheticKeyModifiers {
    SyntheticKeyModifiers {
        command,
        control,
        option,
        shift,
        windows: false,
    }
}

const NO_MODIFIER: SyntheticKeyModifiers = modifiers(false, false, false, false);
const COMMAND: SyntheticKeyModifiers = modifiers(true, false, false, false);
const CONTROL: SyntheticKeyModifiers = modifiers(false, true, false, false);
const COMMAND_OPTION: SyntheticKeyModifiers = modifiers(true, false, true, false);
const COMMAND_SHIFT: SyntheticKeyModifiers = modifiers(true, false, false, true);
const CONTROL_OPTION: SyntheticKeyModifiers = modifiers(false, true, true, false);
const COMMAND_CONTROL_SHIFT: SyntheticKeyModifiers = modifiers(true, true, false, true);

const fn macos(
    chord: &'static [&'static str],
    modifiers: SyntheticKeyModifiers,
    key: SyntheticKey,
    action: &'static str,
) -> SystemWideChord {
    SystemWideChord {
        platform: BlockedChordPlatform::MacOs,
        chord,
        modifiers,
        key,
        action,
    }
}

/// macOS's default system shortcuts, each with where it comes from.
///
/// Two sources are used, both as macOS ships them, before the person changes
/// anything:
///
/// - System Settings > Keyboard > Keyboard Shortcuts, by the section the
///   shortcut is listed under there. Only shortcuts that section enables by
///   default are listed; ones it lists switched off (for example Zoom's
///   Option-Command-8 or "Switch to Desktop 1") are not.
/// - Apple's support article "Mac keyboard shortcuts"
///   (support.apple.com/102650), for the application switcher and Hide
///   Others, which System Settings does not list.
///
/// Left out on purpose: chords that act only inside the frontmost
/// application, even when the system provides them, such as Command-`
/// ("Move focus to next window", which cycles that application's own
/// windows), Command-M, Command-H and Control-Command-F. Chords the session
/// floor refuses outright are in [`BLOCKED_CHORDS`] instead. Keys this
/// module cannot name (the media, brightness, Mission Control, Launchpad and
/// Fn keys) cannot be requested, so they are not listed.
///
/// Windows has no list here yet.
pub const SYSTEM_WIDE_CHORDS: &[SystemWideChord] = &[
    // Keyboard Shortcuts > Spotlight.
    macos(
        &["command", "space"],
        COMMAND,
        SyntheticKey::Space,
        "Show Spotlight search",
    ),
    macos(
        &["command", "option", "space"],
        COMMAND_OPTION,
        SyntheticKey::Space,
        "Show Finder search window",
    ),
    // "Mac keyboard shortcuts": switch between open apps, either way.
    macos(
        &["command", "tab"],
        COMMAND,
        SyntheticKey::Tab,
        "Switch apps",
    ),
    macos(
        &["command", "shift", "tab"],
        COMMAND_SHIFT,
        SyntheticKey::Tab,
        "Switch apps backwards",
    ),
    // "Mac keyboard shortcuts": Option-Command-H hides every other app.
    macos(
        &["command", "option", "h"],
        COMMAND_OPTION,
        SyntheticKey::H,
        "Hide others",
    ),
    // Keyboard Shortcuts > Mission Control.
    macos(
        &["control", "up_arrow"],
        CONTROL,
        SyntheticKey::UpArrow,
        "Mission Control",
    ),
    macos(
        &["control", "down_arrow"],
        CONTROL,
        SyntheticKey::DownArrow,
        "Application windows",
    ),
    macos(
        &["control", "left_arrow"],
        CONTROL,
        SyntheticKey::LeftArrow,
        "Move left a space",
    ),
    macos(
        &["control", "right_arrow"],
        CONTROL,
        SyntheticKey::RightArrow,
        "Move right a space",
    ),
    macos(&["f11"], NO_MODIFIER, SyntheticKey::F11, "Show Desktop"),
    // Keyboard Shortcuts > Screenshots.
    macos(
        &["command", "shift", "digit3"],
        COMMAND_SHIFT,
        SyntheticKey::Digit3,
        "Save picture of screen as a file",
    ),
    macos(
        &["command", "control", "shift", "digit3"],
        COMMAND_CONTROL_SHIFT,
        SyntheticKey::Digit3,
        "Copy picture of screen to the clipboard",
    ),
    macos(
        &["command", "shift", "digit4"],
        COMMAND_SHIFT,
        SyntheticKey::Digit4,
        "Save picture of selected area as a file",
    ),
    macos(
        &["command", "control", "shift", "digit4"],
        COMMAND_CONTROL_SHIFT,
        SyntheticKey::Digit4,
        "Copy picture of selected area to the clipboard",
    ),
    macos(
        &["command", "shift", "digit5"],
        COMMAND_SHIFT,
        SyntheticKey::Digit5,
        "Screenshot and recording options",
    ),
    macos(
        &["command", "shift", "digit6"],
        COMMAND_SHIFT,
        SyntheticKey::Digit6,
        "Save picture of the Touch Bar as a file",
    ),
    macos(
        &["command", "control", "shift", "digit6"],
        COMMAND_CONTROL_SHIFT,
        SyntheticKey::Digit6,
        "Copy picture of the Touch Bar to the clipboard",
    ),
    // Keyboard Shortcuts > Input Sources.
    macos(
        &["control", "space"],
        CONTROL,
        SyntheticKey::Space,
        "Select the previous input source",
    ),
    macos(
        &["control", "option", "space"],
        CONTROL_OPTION,
        SyntheticKey::Space,
        "Select next source in Input menu",
    ),
    // Keyboard Shortcuts > Launchpad & Dock.
    macos(
        &["command", "option", "d"],
        COMMAND_OPTION,
        SyntheticKey::D,
        "Turn Dock hiding on/off",
    ),
    // Keyboard Shortcuts > Keyboard.
    macos(
        &["control", "f1"],
        CONTROL,
        SyntheticKey::F1,
        "Turn keyboard access on or off",
    ),
    macos(
        &["control", "f2"],
        CONTROL,
        SyntheticKey::F2,
        "Move focus to the menu bar",
    ),
    macos(
        &["control", "f3"],
        CONTROL,
        SyntheticKey::F3,
        "Move focus to the Dock",
    ),
    macos(
        &["control", "f4"],
        CONTROL,
        SyntheticKey::F4,
        "Move focus to active or next window",
    ),
    macos(
        &["control", "f5"],
        CONTROL,
        SyntheticKey::F5,
        "Move focus to the window toolbar",
    ),
    macos(
        &["control", "f6"],
        CONTROL,
        SyntheticKey::F6,
        "Move focus to the floating window",
    ),
    macos(
        &["control", "f7"],
        CONTROL,
        SyntheticKey::F7,
        "Change the way Tab moves focus",
    ),
    macos(
        &["control", "f8"],
        CONTROL,
        SyntheticKey::F8,
        "Move focus to status menus",
    ),
    // Keyboard Shortcuts > Accessibility.
    macos(
        &["command", "f5"],
        COMMAND,
        SyntheticKey::F5,
        "Turn VoiceOver on or off",
    ),
    macos(
        &["command", "option", "f5"],
        COMMAND_OPTION,
        SyntheticKey::F5,
        "Show Accessibility controls",
    ),
];

/// The system-wide chord that exactly matches this platform and input:
/// the same exact-modifier matching as [`blocked_chord`], so Command-Shift-Tab
/// is not taken for Command-Tab or the other way round.
pub fn system_wide_chord(
    modifiers: SyntheticKeyModifiers,
    key: SyntheticKey,
    platform: BlockedChordPlatform,
) -> Option<&'static SystemWideChord> {
    SYSTEM_WIDE_CHORDS.iter().find(|chord| {
        chord.platform == platform && chord.modifiers == modifiers && chord.key == key
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_listed_chord_is_found_only_on_its_platform() {
        for blocked in BLOCKED_CHORDS {
            let BlockedKey::Synthetic(key) = blocked.key else {
                assert_eq!(blocked.platform, BlockedChordPlatform::Linux);
                continue;
            };
            assert_eq!(
                blocked_chord(blocked.modifiers, key, blocked.platform),
                Some(blocked),
                "{} chord is absent from the session floor",
                blocked.reason
            );
        }
    }

    #[test]
    fn linux_session_floor_covers_the_required_chords() {
        use LinuxFloorKeysym::*;
        use LinuxResolvedKey::{Keysym, Other, Synthetic};
        use SyntheticKey::*;

        let super_only = modifiers(true, false, false, false);
        let ctrl_alt = modifiers(false, true, true, false);
        let alt = modifiers(false, false, true, false);
        let check = |modifiers, key, sysrq_held, reason| {
            let input = LinuxChordInput::Key {
                modifiers,
                key,
                sysrq_held,
            };
            assert_eq!(
                linux_blocked_chord(Some(input))
                    .unwrap()
                    .map(|row| row.reason),
                reason,
                "{input:?}"
            );
        };
        check(super_only, Synthetic(L), false, Some("lock"));
        check(ctrl_alt, Synthetic(L), false, Some("lock"));
        check(ctrl_alt, Synthetic(ForwardDelete), false, Some("logout"));
        check(ctrl_alt, Synthetic(Backspace), false, Some("logout"));
        for key in [F1, F2, F3, F4, F5, F6, F7, F8, F9, F10, F11, F12] {
            check(ctrl_alt, Synthetic(key), false, Some("vt_switch"));
        }
        check(alt, Keysym(SysRq), false, Some("sysrq"));
        check(ctrl_alt, Other, true, Some("sysrq"));
        check(ctrl_alt, Synthetic(F1), true, Some("sysrq"));
        for key in [PowerOff, Sleep, Suspend, Hibernate] {
            check(
                SyntheticKeyModifiers::NONE,
                Keysym(key),
                false,
                Some("power"),
            );
        }
        check(
            SyntheticKeyModifiers::NONE,
            Keysym(LogOff),
            false,
            Some("logout"),
        );
        check(
            SyntheticKeyModifiers::NONE,
            Keysym(ScreenSaver),
            false,
            Some("lock"),
        );
        check(alt, Keysym(PowerOff), false, Some("power"));
        assert_eq!(
            linux_blocked_chord(Some(LinuxChordInput::SuperTap))
                .unwrap()
                .unwrap()
                .reason,
            "lock"
        );
        assert_eq!(
            BLOCKED_CHORDS
                .iter()
                .filter(|r| r.platform == BlockedChordPlatform::Linux)
                .count(),
            24
        );

        // Ordinary input and harmless near misses do not match a blocked chord.
        check(super_only, Synthetic(S), false, None);
        check(alt, Synthetic(F1), false, None);
        check(SyntheticKeyModifiers::NONE, Other, false, None);
    }

    #[test]
    fn linux_session_floor_refuses_unresolved_input() {
        assert_eq!(linux_blocked_chord(None), Err(LinuxChordUnreadable));
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

    /// The modifiers named in a chord's wire spelling.
    fn spelled_modifiers(chord: &[&str]) -> SyntheticKeyModifiers {
        let mut spelled = SyntheticKeyModifiers::NONE;
        for name in chord {
            match *name {
                "command" => spelled.command = true,
                "control" => spelled.control = true,
                "option" => spelled.option = true,
                "shift" => spelled.shift = true,
                "windows" => spelled.windows = true,
                _ => {}
            }
        }
        spelled
    }

    #[test]
    fn every_chord_is_spelled_with_the_modifiers_it_matches() {
        for blocked in BLOCKED_CHORDS {
            assert_eq!(
                spelled_modifiers(blocked.chord),
                blocked.modifiers,
                "{:?}",
                blocked.chord
            );
        }
        for chord in SYSTEM_WIDE_CHORDS {
            assert_eq!(
                spelled_modifiers(chord.chord),
                chord.modifiers,
                "{:?}",
                chord.chord
            );
        }
    }

    #[test]
    fn every_system_wide_chord_is_found_and_none_is_on_the_session_floor() {
        for chord in SYSTEM_WIDE_CHORDS {
            assert_eq!(
                system_wide_chord(chord.modifiers, chord.key, chord.platform),
                Some(chord),
                "{} is not found",
                chord.action
            );
            assert_eq!(
                blocked_chord(chord.modifiers, chord.key, chord.platform),
                None,
                "{} is refused by the floor already; list it in one place only",
                chord.action
            );
        }
    }

    /// Chords that act only on the application that receives them, however
    /// much they change in it, are not system-wide: the app grant covers
    /// them.
    #[test]
    fn chords_inside_the_application_are_not_system_wide() {
        let command = SyntheticKeyModifiers {
            command: true,
            ..SyntheticKeyModifiers::NONE
        };
        let command_option = SyntheticKeyModifiers {
            command: true,
            option: true,
            ..SyntheticKeyModifiers::NONE
        };
        for (modifiers, key) in [
            (command, SyntheticKey::Q),
            (command, SyntheticKey::W),
            (command, SyntheticKey::Backspace),
            (command, SyntheticKey::C),
            (command, SyntheticKey::M),
            (command, SyntheticKey::H),
            (command, SyntheticKey::Grave),
            (command_option, SyntheticKey::W),
            (SyntheticKeyModifiers::NONE, SyntheticKey::Space),
        ] {
            assert_eq!(
                system_wide_chord(modifiers, key, BlockedChordPlatform::MacOs),
                None,
                "{modifiers:?}+{key:?}"
            );
        }
    }
}
