//! Temporary stand-in for `cerebellum-bridge-protocol`, developed concurrently.
//! Replace this module's types and codec with that crate at integration. The
//! wire definitions below implement the agreed socket contract, not action APIs.

use crate::framing::{read_frame, write_frame};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::io::{self, Read, Write};

pub(crate) const PROTOCOL: u32 = 1;
pub(crate) const MAX_SOCKET_FRAME_BYTES: usize = 16 * 1024 * 1024;
#[cfg(target_os = "macos")]
pub(crate) const CEREBELLUM_REQUIREMENT: &str = "identifier \"ck-cerebellum\" and anchor apple generic and certificate leaf[subject.OU] = \"5R5846NBPW\"";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ParentAttestation {
    pub team_id: Option<String>,
    pub probe_cdhash: Option<String>,
    pub pid: u32,
    pub start_time_micros: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostHello {
    pub protocol: u32,
    pub extension_origin: String,
    pub parent: ParentAttestation,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostAccepted {
    pub protocol: u32,
    pub epoch: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostRefused {
    pub reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RelayFrame {
    // Raw JSON retains numbers, object order and whitespace without interpreting
    // page content. Only the surrounding socket frame is decoded by the host.
    pub message: Box<RawValue>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Frame {
    HostHello(HostHello),
    HostAccepted(HostAccepted),
    HostRefused(HostRefused),
    Relay(RelayFrame),
}

pub(crate) fn read_socket_frame(reader: &mut impl Read) -> io::Result<Option<Frame>> {
    read_frame(reader, MAX_SOCKET_FRAME_BYTES, u32::from_be_bytes)?
        .map(|bytes| decode_socket_frame(&bytes))
        .transpose()
}

fn decode_socket_frame(bytes: &[u8]) -> io::Result<Frame> {
    #[derive(Deserialize)]
    struct FrameType {
        #[serde(rename = "type")]
        kind: String,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RelayWire {
        #[serde(rename = "type")]
        _kind: String,
        message: Box<RawValue>,
    }
    #[derive(Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
    enum ControlFrame {
        #[serde(rename = "host_hello")]
        Hello(HostHello),
        #[serde(rename = "host_accepted")]
        Accepted(HostAccepted),
        #[serde(rename = "host_refused")]
        Refused(HostRefused),
    }
    // Serde's internally tagged enum decoder buffers variant fields, which
    // cannot retain RawValue. Decode the relay directly from the original bytes
    // after identifying the tag, without converting its content into a Value.
    let kind: FrameType = serde_json::from_slice(bytes).map_err(invalid_data)?;
    if kind.kind == "relay" {
        let relay: RelayWire = serde_json::from_slice(bytes).map_err(invalid_data)?;
        return Ok(Frame::Relay(RelayFrame {
            message: relay.message,
        }));
    }
    let control: ControlFrame = serde_json::from_slice(bytes).map_err(invalid_data)?;
    Ok(match control {
        ControlFrame::Hello(hello) => Frame::HostHello(hello),
        ControlFrame::Accepted(accepted) => Frame::HostAccepted(accepted),
        ControlFrame::Refused(refused) => Frame::HostRefused(refused),
    })
}

pub(crate) fn write_socket_frame(writer: &mut impl Write, frame: &Frame) -> io::Result<()> {
    let bytes = serde_json::to_vec(frame).map_err(invalid_data)?;
    write_frame(writer, &bytes, MAX_SOCKET_FRAME_BYTES, u32::to_be_bytes)
}

pub(crate) fn invalid_data(
    error: impl Into<Box<dyn std::error::Error + Send + Sync>>,
) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_codec_uses_big_endian_and_the_agreed_hello_fields() {
        let hello = Frame::HostHello(HostHello {
            protocol: 1,
            extension_origin: "chrome-extension://abcdefghijklmnopabcdefghijklmnop/".into(),
            parent: ParentAttestation {
                team_id: Some("EQHXZ8M8AV".into()),
                probe_cdhash: None,
                pid: 7,
                start_time_micros: 42,
            },
        });
        let mut wire = Vec::new();
        write_socket_frame(&mut wire, &hello).unwrap();
        assert_eq!(&wire[..4], &((wire.len() - 4) as u32).to_be_bytes());
        let expected = serde_json::json!({
            "type": "host_hello", "protocol": 1,
            "extension_origin": "chrome-extension://abcdefghijklmnopabcdefghijklmnop/",
            "parent": { "team_id": "EQHXZ8M8AV", "probe_cdhash": null,
                "pid": 7, "start_time_micros": 42 }
        });
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&wire[4..]).unwrap(),
            expected
        );
    }

    #[test]
    fn socket_codec_refuses_unknown_fields_types_and_oversized_prefixes() {
        for json in [
            r#"{"type":"host_accepted","protocol":1,"epoch":2,"extra":true}"#,
            r#"{"type":"host_refused","reason":"no","extra":true}"#,
            r#"{"type":"relay","message":{},"extra":true}"#,
            r#"{"type":"other"}"#,
        ] {
            let mut wire = Vec::new();
            write_frame(
                &mut wire,
                json.as_bytes(),
                MAX_SOCKET_FRAME_BYTES,
                u32::to_be_bytes,
            )
            .unwrap();
            assert_eq!(
                read_socket_frame(&mut &wire[..]).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        let prefix = (MAX_SOCKET_FRAME_BYTES as u32 + 1).to_be_bytes();
        assert_eq!(
            read_socket_frame(&mut &prefix[..]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
