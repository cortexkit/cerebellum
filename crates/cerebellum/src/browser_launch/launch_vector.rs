use std::ffi::{OsStr, OsString};
use std::path::Path;

use serde::{Deserialize, Serialize};

#[cfg(windows)]
use super::LaunchByteEncoding;

/// Exact executable, arguments and environment submitted to the launcher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedLaunchVector {
    #[serde(with = "cerebellum_core::serde_base64::bytes_compat")]
    pub executable: Vec<u8>,
    #[serde(with = "cerebellum_core::serde_base64::byte_strings_compat")]
    pub arguments: Vec<Vec<u8>>,
    #[serde(with = "cerebellum_core::serde_base64::byte_string_pairs_compat")]
    pub environment: Vec<(Vec<u8>, Vec<u8>)>,
    /// Applies to these byte fields and the enclosing intent's profile path.
    #[cfg(windows)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<LaunchByteEncoding>,
    /// Exact code units submitted to process creation, without the final NUL.
    #[cfg(windows)]
    #[serde(
        rename = "lpCommandLine",
        default,
        skip_serializing_if = "Option::is_none",
        with = "cerebellum_core::serde_base64::optional_bytes"
    )]
    pub lp_command_line: Option<Vec<u8>>,
}

impl VerifiedLaunchVector {
    pub fn new(
        executable: &Path,
        arguments: &[OsString],
        environment: &[(OsString, OsString)],
    ) -> Self {
        Self {
            executable: os_bytes(executable.as_os_str()),
            arguments: arguments
                .iter()
                .map(|arg| os_bytes(arg.as_os_str()))
                .collect(),
            environment: environment
                .iter()
                .map(|(name, value)| (os_bytes(name.as_os_str()), os_bytes(value.as_os_str())))
                .collect(),
            #[cfg(windows)]
            encoding: Some(LaunchByteEncoding::Utf16le),
            #[cfg(windows)]
            lp_command_line: None,
        }
    }
}

/// Preserve the bytes submitted to the platform, not a lossy translation.
pub(super) fn os_bytes(value: &OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        value.as_bytes().to_vec()
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        value.encode_wide().flat_map(u16::to_le_bytes).collect()
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsLaunchJournalInput {
    pub supervisor: crate::profile_custody::SupervisorGeneration,
    pub canonical_profile_path: std::path::PathBuf,
    /// The prepared command line, not including the final NUL.
    pub command_line: Vec<u16>,
}

#[cfg(windows)]
pub(super) fn with_windows_input(
    mut intent: super::AuthorizedLaunchIntent,
    input: Option<&WindowsLaunchJournalInput>,
) -> super::AuthorizedLaunchIntent {
    if let Some(input) = input {
        intent.supervisor_generation = Some(input.supervisor);
        intent.profile.canonical_profile_path = os_bytes(input.canonical_profile_path.as_os_str());
        intent.launch_vector.lp_command_line = Some(
            input
                .command_line
                .iter()
                .copied()
                .flat_map(u16::to_le_bytes)
                .collect(),
        );
    } else {
        // Shared pipeline fixtures can model historical, unmarked intents.
        #[cfg(test)]
        {
            intent.launch_vector.encoding = None;
        }
    }
    intent
}
