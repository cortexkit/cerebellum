use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::marker::PhantomData;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParentAttestation {
    pub team_id: Option<String>,
    pub probe_cdhash: Option<String>,
    pub pid: u32,
    pub start_time_micros: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HostParentAttestation {
    Legacy(ParentAttestation),
    // A Linux or Windows attestation on macOS is a decode error, not a failed
    // parent identity check. The distinction determines the refusal reason.
    #[cfg_attr(target_os = "macos", serde(skip_deserializing))]
    Platform(#[serde(deserialize_with = "deserialize_object")] PlatformParentAttestation),
}

impl HostParentAttestation {
    pub fn as_legacy(&self) -> Option<&ParentAttestation> {
        match self {
            Self::Legacy(parent) => Some(parent),
            Self::Platform(_) => None,
        }
    }
}

impl From<ParentAttestation> for HostParentAttestation {
    fn from(parent: ParentAttestation) -> Self {
        Self::Legacy(parent)
    }
}

impl From<PlatformParentAttestation> for HostParentAttestation {
    fn from(parent: PlatformParentAttestation) -> Self {
        Self::Platform(parent)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PlatformParentAttestation {
    Linux {
        v: AttestationV1,
        browser: LinuxBrowser,
        pid: u32,
        start_ticks: u64,
        #[serde(deserialize_with = "deserialize_object")]
        package: LinuxPackage,
    },
    Windows {
        v: AttestationV1,
        #[serde(deserialize_with = "deserialize_object")]
        chrome: WindowsProcess,
        #[serde(deserialize_with = "deserialize_object")]
        launcher: WindowsProcess,
    },
    #[cfg(feature = "bridge-test-identities")]
    LinuxTest {
        v: AttestationV1,
        pid: u32,
        start_ticks: u64,
    },
    #[cfg(feature = "bridge-test-identities")]
    WindowsTest {
        v: AttestationV1,
        #[serde(deserialize_with = "deserialize_object")]
        parent: WindowsProcess,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct AttestationV1;

impl TryFrom<u8> for AttestationV1 {
    type Error = &'static str;

    fn try_from(version: u8) -> Result<Self, Self::Error> {
        if version == 1 {
            Ok(Self)
        } else {
            Err("unknown parent attestation version")
        }
    }
}

impl From<AttestationV1> for u8 {
    fn from(_: AttestationV1) -> Self {
        1
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LinuxBrowser {
    GoogleChrome,
    Chromium,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinuxPackageManager {
    Dpkg,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxPackage {
    pub manager: LinuxPackageManager,
    pub name: String,
    pub version: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsProcess {
    pub pid: u32,
    pub creation_100ns: u64,
}

// Serde structs also accept positional sequences by default. The platform
// attestations require objects with named fields, including nested records.
fn deserialize_object<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Object<T>(PhantomData<T>);

    impl<'de, T: Deserialize<'de>> Visitor<'de> for Object<T> {
        type Value = T;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an attestation object")
        }

        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }

    deserializer.deserialize_map(Object(PhantomData))
}

#[cfg(test)]
mod tests;
