//! A fail-closed, host-neutral preflight for classic Outlook's Object Model Guard.
//!
//! The supported installation table is deliberately narrow: MSI Office 15.0 and
//! 16.0, x86 or x64. Click-to-Run is unsupported until its virtual-registry
//! overlays and precedence are documented. The identity must come from the
//! running OUTLOOK.EXE, not from a registered default or an Outlook member.
//!
//! | Installation | Locations |
//! | --- | --- |
//! | MSI 15.0 x86 | All eight below; 32-bit machine setting is active |
//! | MSI 15.0 x64 | All eight below; 64-bit machine setting is active |
//! | MSI 16.0 x86 | All eight below; 32-bit machine setting is active |
//! | MSI 16.0 x64 | All eight below; 64-bit machine setting is active |
//! | Click-to-Run, any version/bitness | No supported table; always MayPrompt |
//! | Any other or unidentified installation | No supported table; always MayPrompt |
//!
//! For each supported version, `required_locations` lists the probe envelope:
//! HKLM and HKCU `Software\Microsoft\Office\<version>\Outlook\Security`,
//! and HKLM and HKCU `Software\Policies\Microsoft\Office\<version>\Outlook\Security`,
//! each in the 32-bit and 64-bit views. The 32-bit HKLM view is the
//! `Wow6432Node` path on 64-bit Windows. Only documented settings can permit a
//! read; other overlays are probed so their presence cannot silently permit it.
//! A missing key/value is `Absent`; an access error is `Unreadable`, not absent.
//!
//! Only the HKCU policy mode 3 address-book/address-information settings have
//! documented modern policy rows here. Other explicit programmatic-access
//! policies (registry names starting with `PromptOOM`), policy modes 0/1/2,
//! ordinary user settings, machine policies, mixed policy
//! and machine settings, and conflicting views are conservatively MayPrompt.
//!
//! Decision rows (uncertainty and prompts take precedence over denial):
//!
//! | Row | Parsed configuration | Decision |
//! | --- | --- | --- |
//! | I | Unknown, ambiguous, non-MSI or unlisted version | MayPrompt |
//! | R | Missing, duplicate, unexpected or unreadable location | MayPrompt |
//! | V | Wrong registry type or value outside its documented range | MayPrompt |
//! | U | Undocumented user/machine-policy overlay, policy member or mode | MayPrompt |
//! | C | Conflicting registry views | MayPrompt |
//! | P | Any supported policy prompts, or an absent policy's default could prompt | MayPrompt |
//! | D | No possible prompt, and a supported address-access policy denies | Denied |
//! | A | Supported address policies approve; remaining defaults have Good antivirus | Allowed |
//! | G0 | ObjectModelGuard absent/0 and antivirus Good | Allowed |
//! | G1 | ObjectModelGuard absent/0 and antivirus not Good | MayPrompt |
//! | G2 | ObjectModelGuard 1 (always warn) | MayPrompt |
//! | G3 | ObjectModelGuard 2 (never warn) | Allowed |
//!
//! `MayPrompt` is unavailable for every Windows token. This module never opens
//! Outlook, starts a process, reads a registry key or calls COM.

use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Bitness {
    X86,
    X64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallationKind {
    Msi,
    ClickToRun,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Installation {
    pub major: u16,
    pub minor: u16,
    pub bitness: Bitness,
    pub kind: InstallationKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallationIdentity {
    Unique(Installation),
    Unknown,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Hive {
    LocalMachine,
    CurrentUser,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RegistryView {
    Registry32,
    Registry64,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RegistryLocation {
    pub hive: Hive,
    pub view: RegistryView,
    /// Relative to the hive. The registry view, not a path rewrite, selects WOW64.
    pub key: String,
}

/// The complete set of guard values the collector must query at each location.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Setting {
    ObjectModelGuard,
    AdminSecurityMode,
    PromptOOMSend,
    PromptOOMAddressBookAccess,
    PromptOOMAddressInformationAccess,
    PromptOOMMeetingTaskRequestResponse,
    PromptOOMSaveAs,
    PromptOOMFormulaAccess,
    PromptOOMAddressUserPropertyFind,
}

impl Setting {
    pub const ALL: [Self; 9] = [
        Self::ObjectModelGuard,
        Self::AdminSecurityMode,
        Self::PromptOOMSend,
        Self::PromptOOMAddressBookAccess,
        Self::PromptOOMAddressInformationAccess,
        Self::PromptOOMMeetingTaskRequestResponse,
        Self::PromptOOMSaveAs,
        Self::PromptOOMFormulaAccess,
        Self::PromptOOMAddressUserPropertyFind,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::ObjectModelGuard => "ObjectModelGuard",
            Self::AdminSecurityMode => "AdminSecurityMode",
            Self::PromptOOMSend => "PromptOOMSend",
            Self::PromptOOMAddressBookAccess => "PromptOOMAddressBookAccess",
            Self::PromptOOMAddressInformationAccess => "PromptOOMAddressInformationAccess",
            Self::PromptOOMMeetingTaskRequestResponse => "PromptOOMMeetingTaskRequestResponse",
            Self::PromptOOMSaveAs => "PromptOOMSaveAs",
            Self::PromptOOMFormulaAccess => "PromptOOMFormulaAccess",
            Self::PromptOOMAddressUserPropertyFind => "PromptOOMAddressUserPropertyFind",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum GuardValue {
    #[default]
    Absent,
    Dword(u32),
    /// Includes a registry value with the wrong type or an incomplete DWORD.
    Invalid,
}

pub type GuardValues = BTreeMap<Setting, GuardValue>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocationRead {
    /// All nine settings were queried; an omitted setting was absent.
    Read(GuardValues),
    Unreadable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AntivirusHealth {
    /// Windows Security Center (WSC)'s WscGetSecurityProviderHealth(ANTIVIRUS)
    /// succeeded and returned GOOD.
    Good,
    NotMonitored,
    Poor,
    Snooze,
    /// API failure, unsupported WSC, or a health value not in the WSC enum.
    Unknown,
}

#[derive(Clone, Debug)]
pub struct GuardInput {
    pub installation: InstallationIdentity,
    pub registry: Vec<(RegistryLocation, LocationRead)>,
    pub antivirus: AntivirusHealth,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    MayPrompt,
    Denied,
    Allowed,
}

impl Decision {
    pub const fn may_prompt(self) -> bool {
        matches!(self, Self::MayPrompt)
    }

    pub const fn unavailable_reason(self) -> Option<&'static str> {
        match self {
            Self::MayPrompt => Some("outlook_guard_may_prompt"),
            Self::Denied => Some("permission_missing"),
            Self::Allowed => None,
        }
    }
}

/// Collectors implement this without any Outlook member access. A fresh
/// snapshot is required before each status/data operation, never cached as a
/// permission grant. The later COM adapter must bind it to its running process.
pub trait GuardEnvironment {
    fn guard_input(&self) -> GuardInput;
}

/// Wraps a source so the ability adapter can reject before any member access.
pub struct Guarded<S>(pub S);

impl<S: GuardEnvironment> Guarded<S> {
    pub fn decision(&self) -> Decision {
        decide(&self.0.guard_input())
    }
}

/// `None` means the installation has no supported location/precedence table.
/// The machine setting and bitness-selected WOW64 path are documented at:
/// https://learn.microsoft.com/en-us/troubleshoot/outlook/security/a-program-is-trying-to-send-an-email-message-on-your-behalf
/// The modern HKCU policy path and address-access settings are documented at:
/// https://learn.microsoft.com/en-us/troubleshoot/outlook/security/results-for-advanced-diagnostic-indicate-offline-scan-was-forced
pub fn required_locations(installation: Installation) -> Option<Vec<RegistryLocation>> {
    if installation.kind != InstallationKind::Msi
        || !matches!((installation.major, installation.minor), (15 | 16, 0))
    {
        return None;
    }
    let mut locations = Vec::new();
    for hive in [Hive::LocalMachine, Hive::CurrentUser] {
        for policy in [false, true] {
            for view in [RegistryView::Registry32, RegistryView::Registry64] {
                locations.push(location(installation, hive, policy, view));
            }
        }
    }
    Some(locations)
}

fn location(
    installation: Installation,
    hive: Hive,
    policy: bool,
    view: RegistryView,
) -> RegistryLocation {
    RegistryLocation {
        hive,
        view,
        key: format!(
            "Software\\{}Microsoft\\Office\\{}.{}\\Outlook\\Security",
            if policy { "Policies\\" } else { "" },
            installation.major,
            installation.minor,
        ),
    }
}

/// Pure decision over a complete parsed snapshot. Uncertainty always wins over
/// a deny or allow value, including uncertainty in an otherwise unused view.
pub fn decide(input: &GuardInput) -> Decision {
    let InstallationIdentity::Unique(installation) = input.installation else {
        return Decision::MayPrompt;
    };
    let Some(locations) = required_locations(installation) else {
        return Decision::MayPrompt;
    };
    if input.registry.len() != locations.len() {
        return Decision::MayPrompt;
    }
    let mut reads = BTreeMap::new();
    for (location, read) in &input.registry {
        if !locations.contains(location) || reads.insert(location, read).is_some() {
            return Decision::MayPrompt;
        }
        let LocationRead::Read(values) = read else {
            return Decision::MayPrompt;
        };
        for (&setting, &value) in values {
            let max = if setting == Setting::AdminSecurityMode {
                3
            } else {
                2
            };
            if value == GuardValue::Invalid
                || matches!(value, GuardValue::Dword(number) if number > max)
            {
                return Decision::MayPrompt;
            }
        }
    }

    let mut machine_guard = [GuardValue::Absent; 2];
    let mut user_policy = [GuardValues::new(), GuardValues::new()];
    for hive in [Hive::LocalMachine, Hive::CurrentUser] {
        for policy in [false, true] {
            for (index, view) in [RegistryView::Registry32, RegistryView::Registry64]
                .into_iter()
                .enumerate()
            {
                let key = location(installation, hive, policy, view);
                let Some(LocationRead::Read(values)) = reads.get(&key).copied() else {
                    return Decision::MayPrompt;
                };
                for (&setting, &value) in values {
                    if value == GuardValue::Absent {
                        continue;
                    }
                    match (hive, policy, setting) {
                        (Hive::LocalMachine, false, Setting::ObjectModelGuard) => {
                            machine_guard[index] = value;
                        }
                        (Hive::CurrentUser, true, Setting::ObjectModelGuard) => {
                            return Decision::MayPrompt;
                        }
                        (Hive::CurrentUser, true, _) => {
                            user_policy[index].insert(setting, value);
                        }
                        // No documented permissive precedence for ordinary user
                        // settings, HKLM policy, or other HKLM security settings.
                        _ => return Decision::MayPrompt,
                    }
                }
            }
        }
    }
    let active = match installation.bitness {
        Bitness::X86 => 0,
        Bitness::X64 => 1,
    };
    let guard = match machine_guard[active] {
        GuardValue::Absent => 0,
        GuardValue::Dword(value) => value,
        GuardValue::Invalid => return Decision::MayPrompt,
    };
    if matches!(machine_guard[1 - active], GuardValue::Dword(value) if value != guard)
        || user_policy[0] != user_policy[1]
    {
        return Decision::MayPrompt;
    }
    if !user_policy[0].is_empty() {
        if machine_guard
            .iter()
            .any(|value| *value != GuardValue::Absent)
        {
            // Mixing policy and the machine preference has no supported
            // precedence here, even when one of them appears to allow access.
            return Decision::MayPrompt;
        }
        return policy_decision(&user_policy[0], input.antivirus);
    }
    match guard {
        0 => default_decision(input.antivirus),
        1 => Decision::MayPrompt,
        // MSI 15/16 ObjectModelGuard=2 is "never warn":
        // https://learn.microsoft.com/en-us/troubleshoot/outlook/security/a-program-is-trying-to-send-an-email-message-on-your-behalf
        2 => Decision::Allowed,
        _ => Decision::MayPrompt,
    }
}

fn default_decision(antivirus: AntivirusHealth) -> Decision {
    // Default cross-process access suppresses warnings only with WSC Good:
    // https://learn.microsoft.com/en-us/office/vba/outlook/how-to/security/security-behavior-of-the-outlook-object-model
    if antivirus == AntivirusHealth::Good {
        Decision::Allowed
    } else {
        Decision::MayPrompt
    }
}

fn policy_decision(values: &GuardValues, antivirus: AntivirusHealth) -> Decision {
    let mode = values
        .get(&Setting::AdminSecurityMode)
        .copied()
        .unwrap_or_default();
    if !matches!(mode, GuardValue::Dword(3)) {
        return Decision::MayPrompt;
    }
    let mut denied = false;
    for setting in &Setting::ALL[2..] {
        let value = values.get(setting).copied().unwrap_or_default();
        if value != GuardValue::Absent
            && !matches!(
                setting,
                Setting::PromptOOMAddressBookAccess | Setting::PromptOOMAddressInformationAccess
            )
        {
            // The other PromptOOM settings are documented for 12.0, not for
            // the supported 15/16 installations. Do not extrapolate an allow.
            return Decision::MayPrompt;
        }
        let decision = match value {
            GuardValue::Absent => default_decision(antivirus),
            // Modern AdminSecurityMode=3 and these two address-access policies:
            // https://learn.microsoft.com/en-us/troubleshoot/outlook/security/results-for-advanced-diagnostic-indicate-offline-scan-was-forced
            GuardValue::Dword(0) => Decision::Denied,
            GuardValue::Dword(1) => Decision::MayPrompt,
            GuardValue::Dword(2) => Decision::Allowed,
            _ => Decision::MayPrompt,
        };
        if decision.may_prompt() {
            return Decision::MayPrompt;
        }
        denied |= decision == Decision::Denied;
    }
    if denied {
        Decision::Denied
    } else {
        Decision::Allowed
    }
}

#[cfg(test)]
mod tests;
