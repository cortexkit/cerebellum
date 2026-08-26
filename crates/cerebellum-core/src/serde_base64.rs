//! Serde adapters for byte strings encoded with canonical RFC 4648 base64.
//!
//! JSON's default representation for `Vec<u8>` is an array of decimal numbers.
//! These adapters preserve the bytes while avoiding that representation's large
//! per-byte overhead.

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
type ByteStringPair = (Vec<u8>, Vec<u8>);

/// Encode bytes with the padded RFC 4648 base64 alphabet.
pub fn encode(input: &[u8]) -> String {
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[(first >> 2) as usize] as char);
        output.push(ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize] as char);
        output.push(if chunk.len() > 1 {
            ALPHABET[(((second & 0x0f) << 2) | (third >> 6)) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            ALPHABET[(third & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    output
}

fn alphabet_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode canonical padded RFC 4648 base64.
pub fn decode(input: &str) -> Result<Vec<u8>, &'static str> {
    let bytes = input.as_bytes();
    let (quartets, remainder) = bytes.as_chunks::<4>();
    if !remainder.is_empty() {
        return Err("base64 length is not a multiple of four");
    }
    if quartets.is_empty() {
        return Ok(Vec::new());
    }

    let mut output = Vec::with_capacity(quartets.len() * 3);
    for (index, chunk) in quartets.iter().enumerate() {
        let last = index + 1 == quartets.len();
        let a = alphabet_value(chunk[0]).ok_or("base64 contains an invalid character")?;
        let b = alphabet_value(chunk[1]).ok_or("base64 contains an invalid character")?;
        let c_padding = chunk[2] == b'=';
        let d_padding = chunk[3] == b'=';
        if (c_padding || d_padding) && !last {
            return Err("base64 padding appears before the final quartet");
        }
        if c_padding && !d_padding {
            return Err("base64 has invalid padding");
        }
        let c = if c_padding {
            0
        } else {
            alphabet_value(chunk[2]).ok_or("base64 contains an invalid character")?
        };
        let d = if d_padding {
            0
        } else {
            alphabet_value(chunk[3]).ok_or("base64 contains an invalid character")?
        };
        if c_padding && b & 0x0f != 0 {
            return Err("base64 has non-zero trailing bits");
        }
        if d_padding && !c_padding && c & 0x03 != 0 {
            return Err("base64 has non-zero trailing bits");
        }

        output.push((a << 2) | (b >> 4));
        if !c_padding {
            output.push((b << 4) | (c >> 2));
        }
        if !d_padding {
            output.push((c << 6) | d);
        }
    }
    Ok(output)
}

/// Strict base64 representation for one byte string.
pub mod bytes {
    use super::*;

    pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        decode(&encoded).map_err(D::Error::custom)
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum CompatibleBytes {
    Base64(String),
    Legacy(Vec<u8>),
}

impl CompatibleBytes {
    fn decode<E: serde::de::Error>(self) -> Result<Vec<u8>, E> {
        match self {
            Self::Base64(encoded) => decode(&encoded).map_err(E::custom),
            Self::Legacy(bytes) => Ok(bytes),
        }
    }
}

/// Base64 on write, with legacy JSON number arrays accepted on read.
///
/// This is only for versioned payloads whose old representation must remain
/// readable. New unversioned storage should use [`bytes`] and migrate explicitly.
pub mod bytes_compat {
    use super::*;

    pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        bytes::serialize(value, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        CompatibleBytes::deserialize(deserializer)?.decode()
    }
}

/// Strict base64 representation for an optional byte string.
pub mod optional_bytes {
    use super::*;

    pub fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value
            .as_ref()
            .map(|bytes| encode(bytes))
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|encoded| decode(&encoded).map_err(D::Error::custom))
            .transpose()
    }
}

/// Base64 strings on write, with legacy arrays accepted for each byte string.
pub mod byte_strings_compat {
    use super::*;

    pub fn serialize<S>(value: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value
            .iter()
            .map(|bytes| encode(bytes))
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<CompatibleBytes>::deserialize(deserializer)?
            .into_iter()
            .map(CompatibleBytes::decode)
            .collect()
    }
}

/// Base64 string pairs on write, with legacy byte-array pairs accepted on read.
pub mod byte_string_pairs_compat {
    use super::*;

    pub fn serialize<S>(value: &[(Vec<u8>, Vec<u8>)], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value
            .iter()
            .map(|(name, value)| (encode(name), encode(value)))
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<ByteStringPair>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<(CompatibleBytes, CompatibleBytes)>::deserialize(deserializer)?
            .into_iter()
            .map(|(name, value)| Ok((name.decode()?, value.decode()?)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};

    #[test]
    fn canonical_base64_round_trips_every_remainder_length() {
        for bytes in [b"".as_slice(), b"f", b"fo", b"foo", b"foob", b"fooba"] {
            assert_eq!(decode(&encode(bytes)), Ok(bytes.to_vec()));
        }
    }

    #[test]
    fn decoder_rejects_noncanonical_trailing_bits() {
        assert_eq!(decode("Zh=="), Err("base64 has non-zero trailing bits"));
        assert_eq!(decode("Zm9="), Err("base64 has non-zero trailing bits"));
    }
}
