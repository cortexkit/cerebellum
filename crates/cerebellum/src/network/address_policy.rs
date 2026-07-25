//! Immutable address-policy artifacts and connector-side address selection.
//!
//! The policy is data, not a collection of built-in exceptions. Registration
//! validates the canonical artifact and its mandatory safety floor; runtime
//! classification then uses only the selected artifact and precedence array.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

pub const ADDRESS_POLICY_SCHEMA: &str = "ck-browser-address-policy/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressClass {
    Loopback,
    LinkLocal,
    PrivateUse,
    Multicast,
    Unspecified,
    Metadata,
}

impl AddressClass {
    pub const ALL: [Self; 6] = [
        Self::Loopback,
        Self::LinkLocal,
        Self::PrivateUse,
        Self::Multicast,
        Self::Unspecified,
        Self::Metadata,
    ];
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::LinkLocal => "link_local",
            Self::PrivateUse => "private_use",
            Self::Multicast => "multicast",
            Self::Unspecified => "unspecified",
            Self::Metadata => "metadata",
        }
    }
}

impl fmt::Display for AddressClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
impl FromStr for AddressClass {
    type Err = ();
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "loopback" => Ok(Self::Loopback),
            "link_local" => Ok(Self::LinkLocal),
            "private_use" => Ok(Self::PrivateUse),
            "multicast" => Ok(Self::Multicast),
            "unspecified" => Ok(Self::Unspecified),
            "metadata" => Ok(Self::Metadata),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressPolicyArtifact {
    pub schema: String,
    pub classes: PolicyClassLists,
    pub precedence: Vec<AddressClass>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyClassLists {
    pub loopback: Vec<String>,
    pub link_local: Vec<String>,
    pub private_use: Vec<String>,
    pub multicast: Vec<String>,
    pub unspecified: Vec<String>,
    pub metadata: Vec<String>,
}

impl PolicyClassLists {
    fn get(&self, class: AddressClass) -> &[String] {
        match class {
            AddressClass::Loopback => &self.loopback,
            AddressClass::LinkLocal => &self.link_local,
            AddressClass::PrivateUse => &self.private_use,
            AddressClass::Multicast => &self.multicast,
            AddressClass::Unspecified => &self.unspecified,
            AddressClass::Metadata => &self.metadata,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressPolicyError {
    InvalidJson,
    NonCanonical,
    UnknownOrMissingField,
    InvalidField(&'static str),
    InvalidPrefix(String),
    NonCanonicalPrefix(String),
    DuplicatePrefix(String),
    RedundantPrefix(String),
    InvalidPrecedence,
    MissingMandatoryRange {
        class: AddressClass,
        range: &'static str,
    },
    InvalidDigest,
    DigestMismatch,
}

impl fmt::Display for AddressPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson => f.write_str("address policy JSON is invalid"),
            Self::NonCanonical => f.write_str("address policy is not canonical JSON"),
            Self::UnknownOrMissingField => {
                f.write_str("address policy has an unknown or missing field")
            }
            Self::InvalidField(field) => write!(f, "invalid address policy field {field}"),
            Self::InvalidPrefix(prefix) => write!(f, "invalid CIDR prefix {prefix}"),
            Self::NonCanonicalPrefix(prefix) => write!(f, "noncanonical CIDR prefix {prefix}"),
            Self::DuplicatePrefix(prefix) => write!(f, "duplicate CIDR prefix {prefix}"),
            Self::RedundantPrefix(prefix) => write!(f, "redundant CIDR prefix {prefix}"),
            Self::InvalidPrecedence => f.write_str("invalid address class precedence"),
            Self::MissingMandatoryRange { class, range } => {
                write!(f, "missing {class} range {range}")
            }
            Self::InvalidDigest => f.write_str("invalid policy digest"),
            Self::DigestMismatch => f.write_str("policy digest mismatch"),
        }
    }
}
impl std::error::Error for AddressPolicyError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cidr {
    address: IpAddr,
    prefix_len: u8,
}

impl Cidr {
    fn parse(source: &str) -> Result<Self, AddressPolicyError> {
        let (address, prefix) = source
            .split_once('/')
            .ok_or_else(|| AddressPolicyError::InvalidPrefix(source.to_string()))?;
        if address.is_empty()
            || prefix.is_empty()
            || prefix.contains('/')
            || !prefix.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(AddressPolicyError::InvalidPrefix(source.to_string()));
        }
        let parsed = IpAddr::from_str(address)
            .map_err(|_| AddressPolicyError::InvalidPrefix(source.to_string()))?;
        let prefix_num = prefix
            .parse::<u16>()
            .map_err(|_| AddressPolicyError::InvalidPrefix(source.to_string()))?;
        if prefix_num.to_string() != prefix {
            return Err(AddressPolicyError::NonCanonicalPrefix(source.to_string()));
        }
        let max = if parsed.is_ipv4() { 32 } else { 128 };
        if prefix_num > max {
            return Err(AddressPolicyError::InvalidPrefix(source.to_string()));
        }
        let canonical_address = match parsed {
            IpAddr::V4(value) => {
                if value.to_string() != address {
                    return Err(AddressPolicyError::NonCanonicalPrefix(source.to_string()));
                }
                IpAddr::V4(value)
            }
            IpAddr::V6(value) => {
                if mapped_ipv4(value).is_some() {
                    return Err(AddressPolicyError::InvalidPrefix(source.to_string()));
                }
                if value.to_string() != address {
                    return Err(AddressPolicyError::NonCanonicalPrefix(source.to_string()));
                }
                IpAddr::V6(value)
            }
        };
        let cidr = Self {
            address: canonical_address,
            prefix_len: prefix_num as u8,
        };
        if cidr.network() != cidr.address {
            return Err(AddressPolicyError::NonCanonicalPrefix(source.to_string()));
        }
        Ok(cidr)
    }

    fn network(self) -> IpAddr {
        match self.address {
            IpAddr::V4(value) => {
                IpAddr::V4(Ipv4Addr::from(mask_bytes(&value.octets(), self.prefix_len)))
            }
            IpAddr::V6(value) => {
                IpAddr::V6(Ipv6Addr::from(mask_bytes(&value.octets(), self.prefix_len)))
            }
        }
    }
    fn contains(self, address: IpAddr) -> bool {
        let address = canonical_address(address);
        match (self.address, address) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                prefix_matches(&network.octets(), &candidate.octets(), self.prefix_len)
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                prefix_matches(&network.octets(), &candidate.octets(), self.prefix_len)
            }
            _ => false,
        }
    }
    fn sort_key(self) -> (u8, Vec<u8>, u8) {
        match self.network() {
            IpAddr::V4(value) => (4, value.octets().to_vec(), self.prefix_len),
            IpAddr::V6(value) => (6, value.octets().to_vec(), self.prefix_len),
        }
    }
    fn covers(self, other: Self) -> bool {
        self.contains(other.network()) && (self.prefix_len <= other.prefix_len)
    }
    fn interval(self) -> (u128, u128) {
        match self.network() {
            IpAddr::V4(value) => {
                let start = u32::from(value) as u128;
                let width = if self.prefix_len == 32 {
                    0
                } else {
                    (1u128 << (32 - self.prefix_len)) - 1
                };
                (start, start + width)
            }
            IpAddr::V6(value) => {
                let start = u128::from_be_bytes(value.octets());
                let end = if self.prefix_len == 128 {
                    start
                } else if self.prefix_len == 0 {
                    u128::MAX
                } else {
                    start | (u128::MAX >> self.prefix_len)
                };
                (start, end)
            }
        }
    }
}

fn mask_bytes<const N: usize>(bytes: &[u8; N], prefix_len: u8) -> [u8; N] {
    let mut result = *bytes;
    let full = usize::from(prefix_len / 8);
    let remainder = prefix_len % 8;
    if full < N {
        if remainder != 0 {
            result[full] &= 0xff << (8 - remainder);
        }
        let first_zero = full + usize::from(remainder != 0);
        for byte in &mut result[first_zero..] {
            *byte = 0;
        }
    }
    result
}
fn prefix_matches<const N: usize>(network: &[u8; N], candidate: &[u8; N], prefix_len: u8) -> bool {
    let full = usize::from(prefix_len / 8);
    let remainder = prefix_len % 8;
    if network[..full] != candidate[..full] {
        return false;
    }
    remainder == 0
        || (network[full] & (0xff << (8 - remainder)))
            == (candidate[full] & (0xff << (8 - remainder)))
}
fn canonical_address(address: IpAddr) -> IpAddr {
    canonical_address_for_connector(address)
}

/// Convert IPv4-mapped IPv6 candidates to their embedded binary IPv4 address
/// before policy classification and peer binding.
pub fn canonical_address_for_connector(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(value) => mapped_ipv4(value)
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(value)),
        other => other,
    }
}

fn mapped_ipv4(value: Ipv6Addr) -> Option<Ipv4Addr> {
    let octets = value.octets();
    (octets[..10] == [0; 10] && octets[10..12] == [0xff, 0xff])
        .then(|| Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]))
}

const MANDATORY: &[(&str, AddressClass)] = &[
    ("127.0.0.0/8", AddressClass::Loopback),
    ("::1/128", AddressClass::Loopback),
    ("169.254.0.0/16", AddressClass::LinkLocal),
    ("fe80::/10", AddressClass::LinkLocal),
    ("10.0.0.0/8", AddressClass::PrivateUse),
    ("100.64.0.0/10", AddressClass::PrivateUse),
    ("172.16.0.0/12", AddressClass::PrivateUse),
    ("192.168.0.0/16", AddressClass::PrivateUse),
    ("fc00::/7", AddressClass::PrivateUse),
    ("224.0.0.0/4", AddressClass::Multicast),
    ("ff00::/8", AddressClass::Multicast),
    ("0.0.0.0/8", AddressClass::Unspecified),
    ("192.0.0.0/24", AddressClass::Unspecified),
    ("192.0.2.0/24", AddressClass::Unspecified),
    ("192.88.99.0/24", AddressClass::Unspecified),
    ("198.18.0.0/15", AddressClass::Unspecified),
    ("198.51.100.0/24", AddressClass::Unspecified),
    ("203.0.113.0/24", AddressClass::Unspecified),
    ("240.0.0.0/4", AddressClass::Unspecified),
    ("::/96", AddressClass::Unspecified),
    ("64:ff9b::/96", AddressClass::Unspecified),
    ("64:ff9b:1::/48", AddressClass::Unspecified),
    ("100::/64", AddressClass::Unspecified),
    ("2001:2::/48", AddressClass::Unspecified),
    ("2001:db8::/32", AddressClass::Unspecified),
    ("2002::/16", AddressClass::Unspecified),
    ("169.254.169.254/32", AddressClass::Metadata),
    ("169.254.170.2/32", AddressClass::Metadata),
    ("fd00:ec2::254/128", AddressClass::Metadata),
];

impl AddressPolicyArtifact {
    pub fn parse(bytes: &[u8]) -> Result<Self, AddressPolicyError> {
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| AddressPolicyError::InvalidJson)?;
        if canonical_json_bytes(&value) != bytes {
            return Err(AddressPolicyError::NonCanonical);
        }
        let artifact: Self =
            serde_json::from_value(value).map_err(|_| AddressPolicyError::UnknownOrMissingField)?;
        artifact.validate()?;
        Ok(artifact)
    }
    pub fn parse_pinned(bytes: &[u8], expected_sha256: &str) -> Result<Self, AddressPolicyError> {
        if !valid_digest(expected_sha256) {
            return Err(AddressPolicyError::InvalidDigest);
        }
        let artifact = Self::parse(bytes)?;
        if sha256_hex(bytes) != expected_sha256 {
            return Err(AddressPolicyError::DigestMismatch);
        }
        Ok(artifact)
    }
    pub fn validate(&self) -> Result<(), AddressPolicyError> {
        if self.schema != ADDRESS_POLICY_SCHEMA {
            return Err(AddressPolicyError::InvalidField("schema"));
        }
        let mut compiled = BTreeMap::new();
        for class in AddressClass::ALL {
            let entries = self.classes.get(class);
            if entries.is_empty() {
                return Err(AddressPolicyError::InvalidField(class.as_str()));
            }
            let mut parsed: Vec<Cidr> = Vec::with_capacity(entries.len());
            let mut previous: Option<Cidr> = None;
            for source in entries {
                let cidr = Cidr::parse(source)?;
                if let Some(old) = previous {
                    if old.sort_key() >= cidr.sort_key() {
                        return Err(AddressPolicyError::InvalidField(class.as_str()));
                    }
                }
                if parsed.contains(&cidr) {
                    return Err(AddressPolicyError::DuplicatePrefix(source.clone()));
                }
                if parsed.iter().any(|old| old.covers(cidr)) {
                    return Err(AddressPolicyError::RedundantPrefix(source.clone()));
                }
                previous = Some(cidr);
                parsed.push(cidr);
            }
            compiled.insert(class, parsed);
        }
        if self.precedence.len() != AddressClass::ALL.len()
            || self
                .precedence
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != AddressClass::ALL.len()
        {
            return Err(AddressPolicyError::InvalidPrecedence);
        }
        let index = |class| {
            self.precedence
                .iter()
                .position(|value| *value == class)
                .unwrap()
        };
        if !(index(AddressClass::Metadata) < index(AddressClass::LinkLocal)
            && index(AddressClass::Metadata) < index(AddressClass::PrivateUse)
            && index(AddressClass::Loopback) < index(AddressClass::Unspecified)
            && index(AddressClass::LinkLocal) < index(AddressClass::Unspecified)
            && index(AddressClass::PrivateUse) < index(AddressClass::Unspecified))
        {
            return Err(AddressPolicyError::InvalidPrecedence);
        }
        for (range, class) in MANDATORY {
            let target = Cidr::parse(range).expect("mandatory range is canonical");
            if !covers_range(compiled.get(class).unwrap(), target) {
                return Err(AddressPolicyError::MissingMandatoryRange {
                    class: *class,
                    range,
                });
            }
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_json_bytes(&serde_json::to_value(self).expect("address policy serializes"))
    }
    pub fn digest(&self) -> String {
        sha256_hex(&self.canonical_bytes())
    }
}

fn covers_range(prefixes: &[Cidr], target: Cidr) -> bool {
    let (target_start, target_end) = target.interval();
    let mut intervals: Vec<_> = prefixes
        .iter()
        .copied()
        .filter(|prefix| prefix.address.is_ipv4() == target.address.is_ipv4())
        .map(Cidr::interval)
        .filter(|(start, end)| *end >= target_start && *start <= target_end)
        .collect();
    intervals.sort_unstable();
    let mut cursor = target_start;
    for (start, end) in intervals {
        if start > cursor {
            return false;
        }
        if end >= cursor {
            if end >= target_end {
                return true;
            }
            cursor = end + 1;
        }
    }
    cursor > target_end
}

/// A validated policy ready for connector-owned runtime classification.
#[derive(Debug, Clone)]
pub struct AddressPolicy {
    artifact: AddressPolicyArtifact,
    prefixes: BTreeMap<AddressClass, Vec<Cidr>>,
}

impl AddressPolicy {
    pub fn new(artifact: AddressPolicyArtifact) -> Result<Self, AddressPolicyError> {
        artifact.validate()?;
        let prefixes = AddressClass::ALL
            .iter()
            .map(|class| {
                (
                    *class,
                    artifact
                        .classes
                        .get(*class)
                        .iter()
                        .map(|value| Cidr::parse(value).expect("validated prefix"))
                        .collect(),
                )
            })
            .collect();
        Ok(Self { artifact, prefixes })
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, AddressPolicyError> {
        Self::new(AddressPolicyArtifact::parse(bytes)?)
    }
    pub fn parse_pinned(bytes: &[u8], expected_sha256: &str) -> Result<Self, AddressPolicyError> {
        Self::new(AddressPolicyArtifact::parse_pinned(bytes, expected_sha256)?)
    }
    pub fn artifact(&self) -> &AddressPolicyArtifact {
        &self.artifact
    }
    pub fn digest(&self) -> String {
        self.artifact.digest()
    }
    pub fn classify(&self, address: IpAddr) -> Option<AddressClass> {
        let address = canonical_address(address);
        self.artifact.precedence.iter().copied().find(|class| {
            self.prefixes[class]
                .iter()
                .any(|prefix| prefix.contains(address))
        })
    }
    pub fn allows(&self, address: IpAddr) -> bool {
        self.classify(address).is_none()
    }
    pub fn validate_candidate(&self, source: &str) -> Result<IpAddr, AddressPolicyError> {
        let parsed = source
            .parse::<IpAddr>()
            .map_err(|_| AddressPolicyError::InvalidPrefix(source.to_string()))?;
        Ok(canonical_address(parsed))
    }
}

pub fn canonical_json_bytes(value: &Value) -> Vec<u8> {
    fn write(value: &Value, output: &mut String) {
        match value {
            Value::Null => output.push_str("null"),
            Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
            Value::Number(value) => output.push_str(&value.to_string()),
            Value::String(value) => {
                output.push_str(&serde_json::to_string(value).expect("string serializes"))
            }
            Value::Array(values) => {
                output.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        output.push(',');
                    }
                    write(value, output);
                }
                output.push(']');
            }
            Value::Object(values) => {
                let mut keys: Vec<_> = values.keys().collect();
                keys.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
                output.push('{');
                for (index, key) in keys.into_iter().enumerate() {
                    if index != 0 {
                        output.push(',');
                    }
                    output.push_str(&serde_json::to_string(key).expect("key serializes"));
                    output.push(':');
                    write(&values[key], output);
                }
                output.push('}');
            }
        }
    }
    let mut result = String::new();
    write(value, &mut result);
    result.into_bytes()
}
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
pub fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// The checked-in immutable address-policy fixture used by the browser-plane network module.
pub const ADDRESS_POLICY_FIXTURE: &[u8] =
    include_bytes!("../../resources/b1_s4_address-policy.json");

pub fn fixture() -> Result<AddressPolicy, AddressPolicyError> {
    AddressPolicy::parse(ADDRESS_POLICY_FIXTURE)
}

pub fn fixture_digest() -> String {
    sha256_hex(ADDRESS_POLICY_FIXTURE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_covers_the_minimum_floor_and_classifies_overlaps() {
        let policy = fixture().unwrap();
        assert_eq!(
            policy.classify("169.254.169.254".parse().unwrap()),
            Some(AddressClass::Metadata)
        );
        assert_eq!(
            policy.classify("10.1.2.3".parse().unwrap()),
            Some(AddressClass::PrivateUse)
        );
        assert_eq!(
            policy.classify("192.0.2.1".parse().unwrap()),
            Some(AddressClass::Unspecified)
        );
        assert!(policy.allows("8.8.8.8".parse().unwrap()));
        assert_eq!(policy.classify("::ffff:8.8.8.8".parse().unwrap()), None);
    }

    #[test]
    fn noncanonical_or_redundant_prefixes_are_rejected() {
        let mut artifact: AddressPolicyArtifact =
            serde_json::from_slice(ADDRESS_POLICY_FIXTURE).unwrap();
        artifact.classes.loopback.push("127.0.0.0/9".to_string());
        assert!(matches!(
            artifact.validate(),
            Err(AddressPolicyError::InvalidField("loopback"))
                | Err(AddressPolicyError::RedundantPrefix(_))
        ));
        assert!(Cidr::parse("192.168.1.1/24").is_err());
        assert!(Cidr::parse("10.0.0.0/08").is_err());
        assert!(Cidr::parse("2001:0DB8::/32").is_err());
    }
}
