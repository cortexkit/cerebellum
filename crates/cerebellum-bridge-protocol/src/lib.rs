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
//! Chrome native messaging has a different, native-endian length prefix and a
//! 1 MiB host-to-extension cap: this socket codec is NOT that stdio codec.
//!
//! The server socket is `cortexkit_run_dir()/cerebellum/user-browser.sock`,
//! inside a 0700 directory, with mode 0600. Signing requirements and the origin
//! pin come from these constants, never from a peer-supplied frame.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::io::{self, Read, Write};

mod attestation;
mod gate;
#[cfg(target_os = "linux")]
pub mod linux;
mod paths;
pub mod peer_trailer;
#[cfg(windows)]
pub mod windows;

pub use attestation::{
    AttestationV1, HostParentAttestation, LinuxBrowser, LinuxPackage, LinuxPackageManager,
    ParentAttestation, PlatformParentAttestation, WindowsProcess,
};
pub use gate::classify_bridge_gate;
pub use paths::{linux_socket_path, windows_pipe_name};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub const CEREBELLUM_REQUIREMENT: &str = "identifier \"ck-cerebellum\" and anchor apple generic and certificate leaf[subject.OU] = \"5R5846NBPW\"";
pub const HOST_REQUIREMENT: &str = "identifier \"ck-cerebellum-native-host\" and anchor apple generic and certificate leaf[subject.OU] = \"5R5846NBPW\"";
pub const NATIVE_HOST_NAME: &str = "com.cortexkit.cerebellum";
pub const EXTENSION_ID: &str = "bfmlflnlaflnibiellpjjifdbcifciei";
pub const EXTENSION_ORIGIN: &str = "chrome-extension://bfmlflnlaflnibiellpjjifdbcifciei/";
pub const EXTENSION_PUBLIC_KEY_B64: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyHcwdQ6UQq9vCfCvfUtsoBzv2Nc6Tc0KX7tLbunrVjVO14a70w3gn2gn4ovsxPCO2QijT+7zRr+M/2EAPytHJOZPrqYlRsLJjKP4LqE9NXRI/nVnrZaDmDnqn29JBjnXRGNQ8fl0IXb3QKqOwrUh92w0TK8ZCMaOOHNv6o7ctl3HNor8iKnFR/v+YRTsaCXwzeYkcSN/LL4o4LJVFwAdM5iv2tfJDq3n1DAlHDNZVzsFDPFmLpiOfMphNIQpBopX8ZEH6RjQ4llYakTiYX/UlGX2eZe20e6lCbCt12s7arMA22OMYViKnrVTkMG27vAJRuRydze5SAUydLg3ngycqwIDAQAB";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Frame {
    HostHello {
        protocol: u32,
        extension_origin: String,
        parent: HostParentAttestation,
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
    encode_body(body)
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RelayTag {
    Relay,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRelay<Message> {
    #[serde(rename = "type")]
    tag: RelayTag,
    message: Message,
}

/// Encode the same relay envelope as [`Frame::Relay`] without converting its
/// message into a Value. A transport can preserve number precision, key order
/// and internal whitespace while leaving action interpretation to the server.
pub fn encode_raw_relay(message: &RawValue) -> io::Result<Vec<u8>> {
    encode_body(raw_relay_body(message)?)
}

/// The relay envelope's JSON body without the socket length prefix. The native
/// host hands this exact object to Chrome, whose stdio framing differs from the
/// socket's, so the extension receives the same `{type:"relay",message}` frame.
pub fn raw_relay_body(message: &RawValue) -> io::Result<Vec<u8>> {
    let body = serde_json::to_vec(&RawRelay {
        tag: RelayTag::Relay,
        message,
    })
    .map_err(invalid_data)?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(invalid_data("socket frame exceeds 16 MiB"));
    }
    Ok(body)
}

/// Decode only a relay envelope, retaining the original JSON value bytes.
/// Control frames and unknown envelope fields are refused. Unlike an internally
/// tagged enum, this direct struct decoder does not buffer the message as Value.
pub fn decode_raw_relay_body(body: &[u8]) -> io::Result<Box<RawValue>> {
    if body.len() > MAX_FRAME_BYTES {
        return Err(invalid_data("socket frame exceeds 16 MiB"));
    }
    let relay: RawRelay<Box<RawValue>> = serde_json::from_slice(body).map_err(invalid_data)?;
    Ok(relay.message)
}

fn encode_body(body: Vec<u8>) -> io::Result<Vec<u8>> {
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
    let body = read_body(reader)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "missing socket frame"))?;
    decode_body(&body)
}

/// Read one raw relay, returning None only for EOF between complete frames.
/// Truncated prefixes and bodies remain errors rather than clean disconnects.
pub fn read_raw_relay(reader: &mut impl Read) -> io::Result<Option<Box<RawValue>>> {
    read_body(reader)?
        .map(|body| decode_raw_relay_body(&body))
        .transpose()
}

fn read_body(reader: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut prefix = [0; 4];
    loop {
        match reader.read(&mut prefix[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    reader.read_exact(&mut prefix[1..])?;
    let mut body = vec![0; checked_length(prefix)?];
    reader.read_exact(&mut body)?;
    Ok(Some(body))
}

pub fn write_frame(writer: &mut impl Write, frame: &Frame) -> io::Result<()> {
    writer.write_all(&encode(frame)?)?;
    writer.flush()
}

/// Write a bounded raw relay with the shared socket length prefix.
pub fn write_raw_relay(writer: &mut impl Write, message: &RawValue) -> io::Result<()> {
    writer.write_all(&encode_raw_relay(message)?)?;
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

    #[test]
    fn raw_and_value_relay_codecs_are_wire_compatible() {
        for message in [
            serde_json::json!({"opaque": [1, "λ", true, null]}),
            serde_json::json!([1.5, 18446744073709551615_u64]),
            serde_json::json!("text"),
            serde_json::json!(null),
        ] {
            let raw = RawValue::from_string(serde_json::to_string(&message).unwrap()).unwrap();
            let frame = Frame::Relay { message };
            let raw_wire = encode_raw_relay(&raw).unwrap();
            let value_wire = encode(&frame).unwrap();
            assert_eq!(raw_wire, value_wire);
            assert_eq!(read_frame(&mut raw_wire.as_slice()).unwrap(), frame);
            assert_eq!(
                read_raw_relay(&mut value_wire.as_slice())
                    .unwrap()
                    .unwrap()
                    .get(),
                raw.get()
            );
        }
    }

    #[test]
    fn raw_relay_preserves_precision_order_and_internal_whitespace() {
        let source = r#"{ "z": 1.234567890123456789, "a": [true, null], "text": "café" }"#;
        let raw = RawValue::from_string(source.into()).unwrap();
        let wire = encode_raw_relay(&raw).unwrap();
        let envelope = format!(r#"{{"type":"relay","message":{source}}}"#);
        assert_eq!(&wire[..4], &(envelope.len() as u32).to_be_bytes());
        assert_eq!(&wire[4..], envelope.as_bytes());
        assert_eq!(decode_raw_relay_body(&wire[4..]).unwrap().get(), source);
    }

    #[test]
    fn raw_relay_refuses_unknown_fields_and_control_frames() {
        for body in [
            br#"{"type":"relay","message":{},"extra":true}"#.as_slice(),
            br#"{"type":"relay","type":"relay","message":{}}"#.as_slice(),
            br#"{"type":"host_accepted","protocol":1,"epoch":2}"#.as_slice(),
            br#"{"type":"relay"}"#.as_slice(),
            br#"{"type":"relay","message":not_json}"#.as_slice(),
        ] {
            assert_eq!(
                decode_raw_relay_body(body).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn raw_relay_eof_truncation_and_size_limits_match_socket_framing() {
        assert!(read_raw_relay(&mut [].as_slice()).unwrap().is_none());
        assert_eq!(
            read_frame(&mut [].as_slice()).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        for bytes in [vec![0], vec![0, 0, 0], vec![0, 0, 0, 2, b'{']] {
            assert_eq!(
                read_raw_relay(&mut bytes.as_slice()).unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
        let prefix = ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes();
        assert_eq!(
            read_raw_relay(&mut prefix.as_slice()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let oversized_json = format!("\"{}\"", "x".repeat(MAX_FRAME_BYTES));
        let raw = RawValue::from_string(oversized_json).unwrap();
        assert_eq!(
            encode_raw_relay(&raw).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            decode_raw_relay_body(raw.get().as_bytes())
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        let mut output = Vec::new();
        assert!(write_raw_relay(&mut output, &raw).is_err());
        assert!(output.is_empty());
    }
}
