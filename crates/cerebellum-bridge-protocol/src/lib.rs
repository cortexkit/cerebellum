//! The native-host socket contract, independent of browser execution code.
//!
//! Both endpoints first authenticate the kernel-reported peer with a
//! generation-bound signing check. The host also checks its Chrome parent
//! before connecting. It sends one [`Frame::HostHello`], containing that
//! check's parent generation and the extension origin Chrome supplied. The
//! server verifies the current uid, signed host, pinned origin and parent
//! attestation before answering [`Frame::HostAccepted`]. A refusal closes the
//! connection. Only [`Frame::Relay`] is legal after acceptance.
//!
//! Each frame is UTF-8 JSON preceded by its byte length as a big-endian u32.
//! Lengths above [`MAX_FRAME_BYTES`] are rejected before allocating the body.
//! The host relays `message` without interpreting the extension protocol;
//! extension messages carry their own invocation id and server-assigned epoch.
//! Chrome native messaging has a different, little-endian length prefix and a
//! 1 MiB host-to-extension cap: this socket codec is NOT that stdio codec.
//!
//! The server socket is `cortexkit_run_dir()/cerebellum/user-browser.sock`,
//! inside a 0700 directory, with mode 0600. Signing requirements and the origin
//! pin come from these constants, never from a peer-supplied frame.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub const CEREBELLUM_REQUIREMENT: &str = "identifier \"ck-cerebellum\" and anchor apple generic and certificate leaf[subject.OU] = \"5R5846NBPW\"";
pub const HOST_REQUIREMENT: &str = "identifier \"ck-cerebellum-native-host\" and anchor apple generic and certificate leaf[subject.OU] = \"5R5846NBPW\"";
pub const EXTENSION_ID: &str = "bfmlflnlaflnibiellpjjifdbcifciei";
pub const EXTENSION_ORIGIN: &str = "chrome-extension://bfmlflnlaflnibiellpjjifdbcifciei/";
pub const EXTENSION_PUBLIC_KEY_B64: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyHcwdQ6UQq9vCfCvfUtsoBzv2Nc6Tc0KX7tLbunrVjVO14a70w3gn2gn4ovsxPCO2QijT+7zRr+M/2EAPytHJOZPrqYlRsLJjKP4LqE9NXRI/nVnrZaDmDnqn29JBjnXRGNQ8fl0IXb3QKqOwrUh92w0TK8ZCMaOOHNv6o7ctl3HNor8iKnFR/v+YRTsaCXwzeYkcSN/LL4o4LJVFwAdM5iv2tfJDq3n1DAlHDNZVzsFDPFmLpiOfMphNIQpBopX8ZEH6RjQ4llYakTiYX/UlGX2eZe20e6lCbCt12s7arMA22OMYViKnrVTkMG27vAJRuRydze5SAUydLg3ngycqwIDAQAB";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParentAttestation {
    pub team_id: Option<String>,
    pub probe_cdhash: Option<String>,
    pub pid: u32,
    pub start_time_micros: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Frame {
    HostHello {
        protocol: u32,
        extension_origin: String,
        parent: ParentAttestation,
    },
    HostAccepted {
        protocol: u32,
        epoch: u64,
    },
    HostRefused {
        reason: String,
    },
    Relay {
        message: serde_json::Value,
    },
}

/// Encode one bounded body. Async callers can write the returned bytes without
/// depending on an async runtime in the native host's protocol crate.
pub fn encode(frame: &Frame) -> io::Result<Vec<u8>> {
    let body = serde_json::to_vec(frame).map_err(invalid_data)?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(invalid_data("socket frame exceeds 16 MiB"));
    }
    let mut bytes = Vec::with_capacity(4 + body.len());
    bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&body);
    Ok(bytes)
}

pub fn decode_body(body: &[u8]) -> io::Result<Frame> {
    if body.len() > MAX_FRAME_BYTES {
        return Err(invalid_data("socket frame exceeds 16 MiB"));
    }
    serde_json::from_slice(body).map_err(invalid_data)
}

pub fn checked_length(prefix: [u8; 4]) -> io::Result<usize> {
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(invalid_data("socket frame exceeds 16 MiB"));
    }
    Ok(length)
}

pub fn read_frame(reader: &mut impl Read) -> io::Result<Frame> {
    let mut prefix = [0; 4];
    reader.read_exact(&mut prefix)?;
    let mut body = vec![0; checked_length(prefix)?];
    reader.read_exact(&mut body)?;
    decode_body(&body)
}

pub fn write_frame(writer: &mut impl Write, frame: &Frame) -> io::Result<()> {
    writer.write_all(&encode(frame)?)?;
    writer.flush()
}

fn invalid_data(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use sha2::{Digest, Sha256};

    #[test]
    fn extension_key_derives_the_pinned_id() {
        let der = base64::engine::general_purpose::STANDARD
            .decode(EXTENSION_PUBLIC_KEY_B64)
            .unwrap();
        let hash = Sha256::digest(der);
        let id: String = hash[..16]
            .iter()
            .flat_map(|byte| [byte >> 4, byte & 15])
            .map(|nibble| (b'a' + nibble) as char)
            .collect();
        assert_eq!(id, EXTENSION_ID);
        assert_eq!(EXTENSION_ORIGIN, format!("chrome-extension://{id}/"));
    }

    #[test]
    fn frames_round_trip_with_big_endian_prefix() {
        let frame = Frame::Relay {
            message: serde_json::json!({"opaque": [1, "λ"]}),
        };
        let encoded = encode(&frame).unwrap();
        assert_eq!(
            u32::from_be_bytes(encoded[..4].try_into().unwrap()) as usize,
            encoded.len() - 4
        );
        assert_eq!(read_frame(&mut encoded.as_slice()).unwrap(), frame);
    }

    #[test]
    fn oversized_length_is_rejected_before_reading_body() {
        let prefix = ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes();
        assert_eq!(
            read_frame(&mut prefix.as_slice()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn closed_frames_reject_extra_fields_and_truncation() {
        assert!(
            decode_body(br#"{"type":"host_accepted","protocol":1,"epoch":2,"pid":3}"#).is_err()
        );
        assert!(decode_body(br#"{"type":"host_hello","protocol":1,"extension_origin":"x","parent":{"pid":1,"start_time_micros":2,"team_id":null,"probe_cdhash":null,"extra":true}}"#).is_err());
        assert!(read_frame(&mut [0, 0, 0, 2, b'{'].as_slice()).is_err());
    }
}
