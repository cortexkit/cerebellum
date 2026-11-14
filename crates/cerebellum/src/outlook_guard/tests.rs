use super::*;

fn installation(major: u16, bitness: Bitness) -> Installation {
    Installation {
        major,
        minor: 0,
        bitness,
        kind: InstallationKind::Msi,
    }
}

fn input(installation: Installation) -> GuardInput {
    GuardInput {
        installation: InstallationIdentity::Unique(installation),
        registry: required_locations(installation)
            .unwrap()
            .into_iter()
            .map(|location| (location, LocationRead::Read(GuardValues::new())))
            .collect(),
        antivirus: AntivirusHealth::Good,
    }
}

fn supported() -> impl Iterator<Item = Installation> {
    [15, 16].into_iter().flat_map(|major| {
        [Bitness::X86, Bitness::X64]
            .into_iter()
            .map(move |bitness| installation(major, bitness))
    })
}

fn set(input: &mut GuardInput, index: usize, setting: Setting, value: GuardValue) {
    let LocationRead::Read(values) = &mut input.registry[index].1 else {
        panic!("test location must be readable");
    };
    values.insert(setting, value);
}

fn machine_guard(input: &mut GuardInput, value: GuardValue) {
    let InstallationIdentity::Unique(installation) = input.installation else {
        panic!("test installation must be unique");
    };
    let index = if installation.bitness == Bitness::X86 {
        0
    } else {
        1
    };
    set(input, index, Setting::ObjectModelGuard, value);
}

fn policy(input: &mut GuardInput, setting: Setting, value: GuardValue) {
    for index in [6, 7] {
        set(
            input,
            index,
            Setting::AdminSecurityMode,
            GuardValue::Dword(3),
        );
        set(input, index, setting, value);
    }
}

fn check_locations(major: u16, bitness: Bitness) {
    let actual = required_locations(installation(major, bitness)).unwrap();
    let mut expected = Vec::new();
    for (hive, keys) in [
        (
            Hive::LocalMachine,
            [
                format!(r"Software\Microsoft\Office\{major}.0\Outlook\Security"),
                format!(r"Software\Policies\Microsoft\Office\{major}.0\Outlook\Security"),
            ],
        ),
        (
            Hive::CurrentUser,
            [
                format!(r"Software\Microsoft\Office\{major}.0\Outlook\Security"),
                format!(r"Software\Policies\Microsoft\Office\{major}.0\Outlook\Security"),
            ],
        ),
    ] {
        for key in keys {
            for view in [RegistryView::Registry32, RegistryView::Registry64] {
                expected.push(RegistryLocation {
                    hive,
                    view,
                    key: key.clone(),
                });
            }
        }
    }
    assert_eq!(actual, expected);
}

#[test]
fn locations_msi_15_x86() {
    check_locations(15, Bitness::X86);
}
#[test]
fn locations_msi_15_x64() {
    check_locations(15, Bitness::X64);
}
#[test]
fn locations_msi_16_x86() {
    check_locations(16, Bitness::X86);
}
#[test]
fn locations_msi_16_x64() {
    check_locations(16, Bitness::X64);
}

#[test]
fn row_i_unidentified_ambiguous_c2r_and_unlisted_installations_may_prompt() {
    let mut snapshot = input(installation(16, Bitness::X64));
    for identity in [
        InstallationIdentity::Unknown,
        InstallationIdentity::Ambiguous,
    ] {
        snapshot.installation = identity;
        assert_eq!(decide(&snapshot), Decision::MayPrompt);
    }
    for mut installation in supported() {
        installation.kind = InstallationKind::ClickToRun;
        snapshot.installation = InstallationIdentity::Unique(installation);
        assert!(required_locations(installation).is_none());
        assert_eq!(decide(&snapshot), Decision::MayPrompt);
    }
    for (major, minor) in [(12, 0), (14, 0), (17, 0), (16, 1)] {
        let installation = Installation {
            major,
            minor,
            ..installation(16, Bitness::X64)
        };
        snapshot.installation = InstallationIdentity::Unique(installation);
        assert!(required_locations(installation).is_none());
        assert_eq!(decide(&snapshot), Decision::MayPrompt);
    }
}

#[test]
fn row_r_every_required_location_must_be_present_unique_and_readable() {
    for installation in supported() {
        for index in 0..8 {
            let mut snapshot = input(installation);
            snapshot.registry[index].1 = LocationRead::Unreadable;
            assert_eq!(decide(&snapshot), Decision::MayPrompt, "unreadable {index}");
            let mut snapshot = input(installation);
            snapshot.registry.remove(index);
            assert_eq!(decide(&snapshot), Decision::MayPrompt, "missing {index}");
            let mut snapshot = input(installation);
            snapshot.registry[index] = snapshot.registry[(index + 1) % 8].clone();
            assert_eq!(decide(&snapshot), Decision::MayPrompt, "duplicate {index}");
            let mut snapshot = input(installation);
            snapshot.registry[index].0.key.push_str("-unexpected");
            assert_eq!(decide(&snapshot), Decision::MayPrompt, "unexpected {index}");
        }
    }
}

#[test]
fn row_v_invalid_types_and_out_of_range_values_win_even_over_never_warn() {
    for installation in supported() {
        for index in 0..8 {
            for setting in Setting::ALL {
                let max = if setting == Setting::AdminSecurityMode {
                    3
                } else {
                    2
                };
                for value in [GuardValue::Invalid, GuardValue::Dword(max + 1)] {
                    let mut snapshot = input(installation);
                    machine_guard(&mut snapshot, GuardValue::Dword(2));
                    set(&mut snapshot, index, setting, value);
                    assert_eq!(
                        decide(&snapshot),
                        Decision::MayPrompt,
                        "{index} {setting:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn row_u_undocumented_overlays_modes_and_policy_members_may_prompt() {
    for installation in supported() {
        for index in 0..8 {
            for setting in Setting::ALL {
                let documented = (index < 2 && setting == Setting::ObjectModelGuard)
                    || (index >= 6 && setting != Setting::ObjectModelGuard);
                if documented {
                    continue;
                }
                let mut snapshot = input(installation);
                set(&mut snapshot, index, setting, GuardValue::Dword(2));
                assert_eq!(
                    decide(&snapshot),
                    Decision::MayPrompt,
                    "{index} {setting:?}"
                );
            }
        }
        for mode in [0, 1, 2] {
            let mut snapshot = input(installation);
            for index in [6, 7] {
                set(
                    &mut snapshot,
                    index,
                    Setting::AdminSecurityMode,
                    GuardValue::Dword(mode),
                );
            }
            assert_eq!(decide(&snapshot), Decision::MayPrompt);
        }
        for setting in Setting::ALL[2..].iter().filter(|setting| {
            !matches!(
                setting,
                Setting::PromptOOMAddressBookAccess | Setting::PromptOOMAddressInformationAccess
            )
        }) {
            let mut snapshot = input(installation);
            policy(&mut snapshot, *setting, GuardValue::Dword(2));
            assert_eq!(decide(&snapshot), Decision::MayPrompt);
        }
    }
}

#[test]
fn row_c_conflicting_views_or_machine_and_policy_settings_may_prompt() {
    for installation in supported() {
        let mut snapshot = input(installation);
        set(
            &mut snapshot,
            0,
            Setting::ObjectModelGuard,
            GuardValue::Dword(2),
        );
        set(
            &mut snapshot,
            1,
            Setting::ObjectModelGuard,
            GuardValue::Dword(0),
        );
        assert_eq!(decide(&snapshot), Decision::MayPrompt);
        let mut snapshot = input(installation);
        policy(
            &mut snapshot,
            Setting::PromptOOMAddressBookAccess,
            GuardValue::Dword(2),
        );
        set(
            &mut snapshot,
            6,
            Setting::PromptOOMAddressBookAccess,
            GuardValue::Dword(0),
        );
        assert_eq!(decide(&snapshot), Decision::MayPrompt);
        let mut snapshot = input(installation);
        policy(
            &mut snapshot,
            Setting::PromptOOMAddressBookAccess,
            GuardValue::Dword(0),
        );
        machine_guard(&mut snapshot, GuardValue::Dword(2));
        assert_eq!(decide(&snapshot), Decision::MayPrompt);
    }
}

#[test]
fn row_d_documented_address_policy_denial_is_permission_missing() {
    for installation in supported() {
        for setting in [
            Setting::PromptOOMAddressBookAccess,
            Setting::PromptOOMAddressInformationAccess,
        ] {
            let mut snapshot = input(installation);
            policy(&mut snapshot, setting, GuardValue::Dword(0));
            assert_eq!(decide(&snapshot), Decision::Denied);
            assert!(!decide(&snapshot).may_prompt());
            assert_eq!(
                decide(&snapshot).unavailable_reason(),
                Some("permission_missing")
            );
        }
    }
}

#[test]
fn row_p_prompt_policy_wins_over_denial_and_healthy_antivirus() {
    for installation in supported() {
        let mut snapshot = input(installation);
        policy(
            &mut snapshot,
            Setting::PromptOOMAddressBookAccess,
            GuardValue::Dword(0),
        );
        policy(
            &mut snapshot,
            Setting::PromptOOMAddressInformationAccess,
            GuardValue::Dword(1),
        );
        assert_eq!(decide(&snapshot), Decision::MayPrompt);
        assert_eq!(
            decide(&snapshot).unavailable_reason(),
            Some("outlook_guard_may_prompt")
        );
    }
}

#[test]
fn row_a_documented_address_policy_approval_with_healthy_defaults_allows() {
    for installation in supported() {
        let mut snapshot = input(installation);
        policy(
            &mut snapshot,
            Setting::PromptOOMAddressBookAccess,
            GuardValue::Dword(2),
        );
        policy(
            &mut snapshot,
            Setting::PromptOOMAddressInformationAccess,
            GuardValue::Dword(2),
        );
        assert_eq!(decide(&snapshot), Decision::Allowed);
        assert_eq!(decide(&snapshot).unavailable_reason(), None);
        // The other guarded operations are absent, so their default still
        // depends on antivirus health rather than inheriting this approval.
        snapshot.antivirus = AntivirusHealth::Poor;
        assert_eq!(decide(&snapshot), Decision::MayPrompt);
    }
}

#[test]
fn row_g0_absent_or_zero_guard_and_good_antivirus_allow() {
    for installation in supported() {
        for value in [GuardValue::Absent, GuardValue::Dword(0)] {
            let mut snapshot = input(installation);
            machine_guard(&mut snapshot, value);
            assert_eq!(decide(&snapshot), Decision::Allowed);
            snapshot.registry.reverse();
            assert_eq!(decide(&snapshot), Decision::Allowed);
        }
    }
}

#[test]
fn row_g1_absent_or_zero_guard_with_each_non_good_wsc_state_may_prompt() {
    for installation in supported() {
        for value in [GuardValue::Absent, GuardValue::Dword(0)] {
            for antivirus in [
                AntivirusHealth::NotMonitored,
                AntivirusHealth::Poor,
                AntivirusHealth::Snooze,
                AntivirusHealth::Unknown,
            ] {
                let mut snapshot = input(installation);
                machine_guard(&mut snapshot, value);
                snapshot.antivirus = antivirus;
                assert_eq!(decide(&snapshot), Decision::MayPrompt);
            }
        }
    }
}

#[test]
fn row_g2_always_warn_prompts_even_with_good_antivirus() {
    for installation in supported() {
        let mut snapshot = input(installation);
        machine_guard(&mut snapshot, GuardValue::Dword(1));
        assert_eq!(decide(&snapshot), Decision::MayPrompt);
    }
}

#[test]
fn row_g3_never_warn_allows_even_with_unknown_antivirus() {
    for installation in supported() {
        let mut snapshot = input(installation);
        machine_guard(&mut snapshot, GuardValue::Dword(2));
        snapshot.antivirus = AntivirusHealth::Unknown;
        assert_eq!(decide(&snapshot), Decision::Allowed);
        // A same-valued explicit setting in the other view is not a conflict.
        set(
            &mut snapshot,
            0,
            Setting::ObjectModelGuard,
            GuardValue::Dword(2),
        );
        set(
            &mut snapshot,
            1,
            Setting::ObjectModelGuard,
            GuardValue::Dword(2),
        );
        assert_eq!(decide(&snapshot), Decision::Allowed);
    }
}

#[test]
fn uncertainty_precedes_a_documented_policy_denial() {
    let mut snapshot = input(installation(16, Bitness::X64));
    policy(
        &mut snapshot,
        Setting::PromptOOMAddressBookAccess,
        GuardValue::Dword(0),
    );
    snapshot.registry[2].1 = LocationRead::Unreadable;
    assert_eq!(decide(&snapshot), Decision::MayPrompt);
}

#[test]
fn collector_names_pin_every_guard_setting() {
    assert_eq!(
        Setting::ALL.map(Setting::name),
        [
            "ObjectModelGuard",
            "AdminSecurityMode",
            "PromptOOMSend",
            "PromptOOMAddressBookAccess",
            "PromptOOMAddressInformationAccess",
            "PromptOOMMeetingTaskRequestResponse",
            "PromptOOMSaveAs",
            "PromptOOMFormulaAccess",
            "PromptOOMAddressUserPropertyFind",
        ]
    );
}
