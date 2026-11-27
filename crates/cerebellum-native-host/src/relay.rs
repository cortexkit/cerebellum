use crate::framing::{read_native_frame, write_native_frame};
use cerebellum_bridge_protocol::{
    decode_raw_relay_body, raw_relay_body, read_frame as read_socket_control_frame, read_raw_relay,
    write_frame as write_socket_control_frame, write_raw_relay, Frame, ParentAttestation,
    PROTOCOL_VERSION,
};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::time::Duration;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn establish_session(
    extension_origin: String,
    check_parent: impl FnOnce() -> io::Result<ParentAttestation>,
    connect: impl FnOnce() -> io::Result<UnixStream>,
    check_server: impl FnOnce(&UnixStream) -> io::Result<()>,
) -> io::Result<(UnixStream, u64)> {
    // This ordering is a trust boundary: a local caller of the signed host must
    // not even connect, and a fake server must receive neither hello nor content.
    let parent = check_parent()?;
    if parent.team_id.is_some() == parent.probe_cdhash.is_some() {
        return Err(invalid_data(
            "parent identity must name exactly one signer or probe hash",
        ));
    }
    let mut socket = connect()?;
    socket.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    socket.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    check_server(&socket)?;
    write_socket_control_frame(
        &mut socket,
        &Frame::HostHello {
            protocol: PROTOCOL_VERSION,
            extension_origin,
            parent: parent.into(),
        },
    )?;
    let epoch = match read_socket_control_frame(&mut socket)? {
        Frame::HostAccepted { protocol, epoch } if protocol == PROTOCOL_VERSION => epoch,
        Frame::HostRefused { .. } => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "bridge refused host",
            ));
        }
        _ => return Err(invalid_data("expected host acceptance")),
    };
    // The bridge, not the host, assigns action deadlines. An idle native port
    // must survive beyond the bounded handshake; writes remain bounded.
    socket.set_read_timeout(None)?;
    Ok((socket, epoch))
}

/// Why a relay stopped. Shipped hosts never record it: stdout carries
/// native-messaging frames and Chrome discards stderr, so the host has nowhere
/// to report it. Only the Chrome for Testing probe build writes it down, so a
/// failed probe can say which side closed the port.
#[derive(Debug)]
pub(crate) enum RelayEnd {
    /// Chrome closed the native port: stdin reached EOF between frames.
    ChromeClosed,
    /// Cerebellum closed the socket between frames.
    SocketClosed,
    /// Reading a frame from Chrome failed, or the frame was not a relay
    /// envelope (bad length prefix, truncation, invalid JSON, control frame).
    ChromeInput(io::Error),
    /// Writing a relayed message to the cerebellum socket failed.
    SocketWrite(io::Error),
    /// Reading or decoding a frame from the cerebellum socket failed.
    SocketInput(io::Error),
    /// Writing a native-messaging frame to Chrome failed, including a message
    /// above Chrome's 1 MiB host-to-extension limit.
    ChromeWrite(io::Error),
    /// Cloning the socket or spawning the thread that relays Chrome's input to
    /// the cerebellum socket failed.
    Setup(io::Error),
}

impl RelayEnd {
    /// A clean close by either side is a normal end of the native port.
    pub(crate) fn into_result(self) -> io::Result<()> {
        match self {
            Self::ChromeClosed | Self::SocketClosed => Ok(()),
            Self::ChromeInput(error)
            | Self::SocketWrite(error)
            | Self::SocketInput(error)
            | Self::ChromeWrite(error)
            | Self::Setup(error) => Err(error),
        }
    }
}

impl fmt::Display for RelayEnd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChromeClosed => write!(f, "EOF from Chrome (native port closed)"),
            Self::SocketClosed => write!(f, "EOF from the cerebellum socket"),
            Self::ChromeInput(error) => write!(f, "framing or read error from Chrome: {error}"),
            Self::SocketWrite(error) => write!(f, "write error to the cerebellum socket: {error}"),
            Self::SocketInput(error) => {
                write!(
                    f,
                    "framing or read error from the cerebellum socket: {error}"
                )
            }
            Self::ChromeWrite(error) => write!(f, "write error to Chrome: {error}"),
            Self::Setup(error) => write!(f, "relay setup failed: {error}"),
        }
    }
}

/// Relay one accepted session until either side closes.
///
/// The extension speaks the socket's own frame objects (extension/PROTOCOL.md):
/// it waits for `{type:"host_accepted",protocol,epoch}` before it treats the
/// port as connected, and it sends and accepts only `{type:"relay",message}`.
/// The host therefore forwards the acceptance it consumed during the handshake,
/// then passes relay envelopes through whole in both directions. Unwrapping
/// them makes the extension reject the first command as an unknown frame and
/// close the port.
pub(crate) fn relay(
    mut socket: UnixStream,
    epoch: u64,
    mut chrome_input: impl Read + Send + 'static,
    chrome_output: &mut impl Write,
) -> RelayEnd {
    let accepted = serde_json::to_vec(&Frame::HostAccepted {
        protocol: PROTOCOL_VERSION,
        epoch,
    })
    .map_err(invalid_data)
    .and_then(|accepted| write_native_frame(chrome_output, &accepted));
    if let Err(error) = accepted {
        let _ = socket.shutdown(Shutdown::Both);
        return RelayEnd::ChromeWrite(error);
    }
    let mut input_socket = match socket.try_clone() {
        Ok(socket) => socket,
        Err(error) => return RelayEnd::Setup(error),
    };
    let (sender, receiver) = mpsc::sync_channel(1);
    let input_thread = std::thread::Builder::new()
        .name("native-messaging-input".into())
        .spawn(move || {
            let end = relay_from_chrome(&mut chrome_input, &mut input_socket);
            // Report before shutting the socket down: the output side then sees
            // EOF and can tell that this side ended first.
            let _ = sender.send(end);
            let _ = input_socket.shutdown(Shutdown::Both);
        });
    if let Err(error) = input_thread {
        let _ = socket.shutdown(Shutdown::Both);
        return RelayEnd::Setup(error);
    }
    let to_chrome = relay_to_chrome(&mut socket, chrome_output);
    let _ = socket.shutdown(Shutdown::Both);
    // Do not join a thread blocked on Chrome's stdin after a server disconnect.
    // Returning from main exits the host and closes the native port immediately.
    match (to_chrome, receiver.try_recv()) {
        // The socket EOF was caused by the Chrome side shutting it down.
        (RelayEnd::SocketClosed, Ok(from_chrome)) => from_chrome,
        (to_chrome, _) => to_chrome,
    }
}

fn relay_from_chrome(input: &mut impl Read, socket: &mut impl Write) -> RelayEnd {
    loop {
        let frame = match read_native_frame(input) {
            Ok(Some(frame)) => frame,
            Ok(None) => return RelayEnd::ChromeClosed,
            Err(error) => return RelayEnd::ChromeInput(error),
        };
        // Only relay envelopes may come from the extension; a control frame
        // such as a forged host_hello is refused rather than forwarded.
        let message = match decode_raw_relay_body(&frame) {
            Ok(message) => message,
            Err(error) => return RelayEnd::ChromeInput(error),
        };
        if let Err(error) = write_raw_relay(socket, &message) {
            return RelayEnd::SocketWrite(error);
        }
    }
}

fn relay_to_chrome(socket: &mut impl Read, output: &mut impl Write) -> RelayEnd {
    loop {
        let message = match read_raw_relay(socket) {
            Ok(Some(message)) => message,
            Ok(None) => return RelayEnd::SocketClosed,
            Err(error) => return RelayEnd::SocketInput(error),
        };
        if let Err(error) =
            raw_relay_body(&message).and_then(|body| write_native_frame(output, &body))
        {
            return RelayEnd::ChromeWrite(error);
        }
    }
}

fn invalid_data(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::value::RawValue;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn parent() -> io::Result<ParentAttestation> {
        Ok(ParentAttestation {
            team_id: Some("EQHXZ8M8AV".into()),
            probe_cdhash: None,
            pid: 12,
            start_time_micros: 34,
        })
    }

    fn origin() -> String {
        "chrome-extension://abcdefghijklmnopabcdefghijklmnop/".into()
    }

    #[test]
    fn rejected_parent_never_calls_the_socket_connector() {
        let connected = AtomicBool::new(false);
        let result = establish_session(
            origin(),
            || {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "not Chrome",
                ))
            },
            || {
                connected.store(true, Ordering::SeqCst);
                Err(io::Error::other("unexpected connection"))
            },
            |_| Ok(()),
        );
        assert!(!connected.load(Ordering::SeqCst));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn rejected_server_receives_no_hello_or_extension_frames() {
        let (host, mut stand_in) = UnixStream::pair().unwrap();
        let result = establish_session(
            origin(),
            parent,
            || Ok(host),
            |_| {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unsigned server",
                ))
            },
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        let mut bytes = Vec::new();
        stand_in.read_to_end(&mut bytes).unwrap();
        assert!(bytes.is_empty());
    }

    #[test]
    fn hello_attests_parent_and_origin_once_before_acceptance() {
        let (host, mut server) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            let Frame::HostHello {
                protocol,
                extension_origin,
                parent: attested_parent,
            } = read_socket_control_frame(&mut server).unwrap()
            else {
                panic!("expected hello");
            };
            assert_eq!(protocol, 1);
            assert_eq!(extension_origin, origin());
            assert_eq!(attested_parent.as_legacy(), Some(&parent().unwrap()));
            write_socket_control_frame(
                &mut server,
                &Frame::HostAccepted {
                    protocol: 1,
                    epoch: 23,
                },
            )
            .unwrap();
            server
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            assert!(read_raw_relay(&mut server).unwrap().is_none());
        });
        let (socket, epoch) = establish_session(origin(), parent, || Ok(host), |_| Ok(())).unwrap();
        assert_eq!(epoch, 23);
        drop(socket);
        server.join().unwrap();
    }

    #[test]
    fn refusal_wrong_protocol_and_early_relay_never_start_relaying() {
        for reply in [
            Frame::HostRefused {
                reason: "wrong_origin".into(),
            },
            Frame::HostAccepted {
                protocol: 2,
                epoch: 3,
            },
            Frame::Relay {
                message: serde_json::json!({}),
            },
        ] {
            let (host, mut server) = UnixStream::pair().unwrap();
            let server = std::thread::spawn(move || {
                assert!(matches!(
                    read_socket_control_frame(&mut server).unwrap(),
                    Frame::HostHello { .. }
                ));
                write_socket_control_frame(&mut server, &reply).unwrap();
                let mut bytes = Vec::new();
                server.read_to_end(&mut bytes).unwrap();
                assert!(bytes.is_empty());
            });
            assert!(establish_session(origin(), parent, || Ok(host), |_| Ok(())).is_err());
            server.join().unwrap();
        }
    }

    /// Chrome-side frame for a relay message, as the extension posts it.
    fn chrome_relay(message: &str) -> Vec<u8> {
        format!(r#"{{"type":"relay","message":{message}}}"#).into_bytes()
    }

    #[test]
    fn both_relay_directions_keep_the_envelope_and_preserve_message_bytes() {
        let messages = [
            r#"{ "a": 1.234567890123456789, "z": [true, null], "text": "café" }"#,
            r#"["second", 18446744073709551615]"#,
        ];
        let mut chrome_wire = Vec::new();
        for message in messages {
            write_native_frame(&mut chrome_wire, &chrome_relay(message)).unwrap();
        }
        let mut socket_wire = Vec::new();
        assert!(matches!(
            relay_from_chrome(&mut Cursor::new(&chrome_wire), &mut socket_wire),
            RelayEnd::ChromeClosed
        ));
        let mut decoded = &socket_wire[..];
        for expected in messages {
            let message = read_raw_relay(&mut decoded).unwrap().unwrap();
            assert_eq!(message.get(), expected);
        }
        assert!(decoded.is_empty());
        let mut output = Vec::new();
        assert!(matches!(
            relay_to_chrome(&mut &socket_wire[..], &mut output),
            RelayEnd::SocketClosed
        ));
        assert_eq!(output, chrome_wire);
    }

    #[test]
    fn malformed_chrome_json_and_control_frames_after_acceptance_are_refused() {
        for refused in [
            b"not json".as_slice(),
            // A bare message without the relay envelope.
            br#"{"id":1,"epoch":2,"body":{"type":"attached"}}"#.as_slice(),
            // The extension may never speak for the host.
            br#"{"type":"host_accepted","protocol":1,"epoch":2}"#.as_slice(),
        ] {
            let mut chrome_wire = Vec::new();
            write_native_frame(&mut chrome_wire, refused).unwrap();
            let mut socket_wire = Vec::new();
            let end = relay_from_chrome(&mut &chrome_wire[..], &mut socket_wire);
            assert!(
                matches!(&end, RelayEnd::ChromeInput(error) if error.kind() == io::ErrorKind::InvalidData)
            );
            assert!(socket_wire.is_empty());
        }
        let mut socket_wire = Vec::new();
        write_socket_control_frame(
            &mut socket_wire,
            &Frame::HostAccepted {
                protocol: 1,
                epoch: 3,
            },
        )
        .unwrap();
        let mut output = Vec::new();
        assert!(matches!(
            relay_to_chrome(&mut &socket_wire[..], &mut output),
            RelayEnd::SocketInput(_)
        ));
        assert!(output.is_empty());
    }

    struct Session {
        server: UnixStream,
        chrome_writer: UnixStream,
        chrome_reader: UnixStream,
        relay: std::thread::JoinHandle<RelayEnd>,
    }

    fn session(epoch: u64) -> Session {
        let (host, server) = UnixStream::pair().unwrap();
        let (chrome_input, chrome_writer) = UnixStream::pair().unwrap();
        let (chrome_reader, mut chrome_output) = UnixStream::pair().unwrap();
        chrome_reader
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let relay =
            std::thread::spawn(move || relay(host, epoch, chrome_input, &mut chrome_output));
        Session {
            server,
            chrome_writer,
            chrome_reader,
            relay,
        }
    }

    fn chrome_frame(reader: &mut UnixStream) -> serde_json::Value {
        serde_json::from_slice(&read_native_frame(reader).unwrap().unwrap()).unwrap()
    }

    #[test]
    fn relay_moves_both_directions_and_does_not_wait_for_stdin_on_server_eof() {
        let mut s = session(23);
        assert_eq!(
            chrome_frame(&mut s.chrome_reader),
            serde_json::json!({"type":"host_accepted","protocol":1,"epoch":23})
        );
        write_native_frame(
            &mut s.chrome_writer,
            &chrome_relay(r#"{"content":"input"}"#),
        )
        .unwrap();
        let message = read_raw_relay(&mut s.server).unwrap().unwrap();
        assert_eq!(message.get(), r#"{"content":"input"}"#);
        write_raw_relay(
            &mut s.server,
            &RawValue::from_string(r#"{"content":"output"}"#.into()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            read_native_frame(&mut s.chrome_reader).unwrap().unwrap(),
            chrome_relay(r#"{"content":"output"}"#)
        );
        drop(s.server);
        assert!(matches!(s.relay.join().unwrap(), RelayEnd::SocketClosed));
        drop(s.chrome_writer);
    }

    #[test]
    fn chrome_closing_the_port_is_reported_as_the_cause_not_the_socket_eof_it_triggers() {
        let mut s = session(5);
        chrome_frame(&mut s.chrome_reader);
        drop(s.chrome_writer);
        let end = s.relay.join().unwrap();
        assert!(matches!(end, RelayEnd::ChromeClosed));
        // Chrome closing the port is a normal end: the host exits successfully.
        assert!(end.into_result().is_ok());
        // The host closes the socket so cerebellum sees the port go away.
        assert!(read_raw_relay(&mut s.server).unwrap().is_none());
    }

    #[test]
    fn an_unwrapped_extension_message_ends_the_relay_as_a_chrome_framing_error() {
        let mut s = session(5);
        chrome_frame(&mut s.chrome_reader);
        write_native_frame(&mut s.chrome_writer, br#"{"id":1,"epoch":5,"body":{}}"#).unwrap();
        // Check the socket before joining: a host that wrongly forwarded the
        // message would keep relaying, and the join would never return.
        assert!(read_raw_relay(&mut s.server).unwrap().is_none());
        let end = s.relay.join().unwrap();
        assert!(matches!(&end, RelayEnd::ChromeInput(_)), "{end}");
        assert!(end
            .to_string()
            .starts_with("framing or read error from Chrome"));
        assert!(end.into_result().is_err());
    }

    /// Frames shared with extension/tests/native.test.mjs, which feeds the same
    /// host-to-extension frames to the real NativeBridge and expects exactly the
    /// extension-to-host frames back. The host must produce and accept those
    /// frames as they are; neither side may add or strip an envelope.
    const EXTENSION_WIRE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../extension/tests/native-host-wire.json"
    ));

    #[test]
    fn host_speaks_the_frames_the_extension_accepts_in_both_directions() {
        let wire: serde_json::Value = serde_json::from_str(EXTENSION_WIRE).unwrap();
        let epoch = wire["epoch"].as_u64().unwrap();
        let to_extension = wire["host_to_extension"].as_array().unwrap();
        let from_extension = wire["extension_to_host"].as_array().unwrap();
        let mut s = session(epoch);
        // The extension treats the port as connected only after this frame.
        assert_eq!(chrome_frame(&mut s.chrome_reader), to_extension[0]);
        for expected in &to_extension[1..] {
            let message = serde_json::to_string(&expected["message"]).unwrap();
            write_raw_relay(&mut s.server, &RawValue::from_string(message).unwrap()).unwrap();
            assert_eq!(&chrome_frame(&mut s.chrome_reader), expected);
        }
        for frame in from_extension {
            write_native_frame(&mut s.chrome_writer, &serde_json::to_vec(frame).unwrap()).unwrap();
            assert_eq!(
                read_socket_control_frame(&mut s.server).unwrap(),
                Frame::Relay {
                    message: frame["message"].clone()
                }
            );
        }
        drop(s.server);
        assert!(matches!(s.relay.join().unwrap(), RelayEnd::SocketClosed));
    }

    #[test]
    fn shared_host_hello_decodes_through_the_host_control_path() {
        let hello = Frame::HostHello {
            protocol: PROTOCOL_VERSION,
            extension_origin: origin(),
            parent: parent().unwrap().into(),
        };
        let wire = cerebellum_bridge_protocol::encode(&hello).unwrap();
        assert_eq!(read_socket_control_frame(&mut &wire[..]).unwrap(), hello);
    }

    #[test]
    fn host_accepted_encoding_is_readable_by_the_shared_codec() {
        let accepted = Frame::HostAccepted {
            protocol: PROTOCOL_VERSION,
            epoch: 23,
        };
        let mut wire = Vec::new();
        write_socket_control_frame(&mut wire, &accepted).unwrap();
        assert_eq!(
            cerebellum_bridge_protocol::read_frame(&mut &wire[..]).unwrap(),
            accepted
        );
    }

    #[test]
    fn shared_relay_and_host_stdio_paths_interoperate_both_directions() {
        let message = serde_json::json!({"opaque": [1, "λ", true, null]});
        let shared_frame = Frame::Relay {
            message: message.clone(),
        };
        let shared_wire = cerebellum_bridge_protocol::encode(&shared_frame).unwrap();
        let mut chrome_wire = Vec::new();
        relay_to_chrome(&mut &shared_wire[..], &mut chrome_wire);
        // Chrome receives the shared frame object itself, envelope included.
        let chrome_message = read_native_frame(&mut &chrome_wire[..]).unwrap().unwrap();
        assert_eq!(chrome_message, serde_json::to_vec(&shared_frame).unwrap());

        let mut host_wire = Vec::new();
        relay_from_chrome(&mut &chrome_wire[..], &mut host_wire);
        assert_eq!(host_wire, shared_wire);
        assert_eq!(
            cerebellum_bridge_protocol::read_frame(&mut &host_wire[..]).unwrap(),
            shared_frame
        );
    }
}
