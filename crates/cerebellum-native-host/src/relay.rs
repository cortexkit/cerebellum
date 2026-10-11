use crate::framing::{read_native_frame, write_native_frame};
use crate::protocol::{
    invalid_data, read_socket_frame, write_socket_frame, Frame, HostHello, ParentAttestation,
    RelayFrame, PROTOCOL,
};
use serde_json::value::RawValue;
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
    write_socket_frame(
        &mut socket,
        &Frame::HostHello(HostHello {
            protocol: PROTOCOL,
            extension_origin,
            parent,
        }),
    )?;
    let epoch = match read_socket_frame(&mut socket)? {
        Some(Frame::HostAccepted(accepted)) if accepted.protocol == PROTOCOL => accepted.epoch,
        Some(Frame::HostRefused(_)) => {
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

pub(crate) fn relay(
    mut socket: UnixStream,
    mut chrome_input: impl Read + Send + 'static,
    chrome_output: &mut impl Write,
) -> io::Result<()> {
    let mut input_socket = socket.try_clone()?;
    let (sender, receiver) = mpsc::sync_channel(1);
    let _input_thread = std::thread::Builder::new()
        .name("native-messaging-input".into())
        .spawn(move || {
            let result = relay_from_chrome(&mut chrome_input, &mut input_socket);
            let _ = sender.send(result);
            let _ = input_socket.shutdown(Shutdown::Both);
        })?;
    let result = relay_to_chrome(&mut socket, chrome_output);
    let _ = socket.shutdown(Shutdown::Both);
    result?;
    if let Ok(input_result) = receiver.try_recv() {
        input_result?;
    }
    // Do not join a thread blocked on Chrome's stdin after a server disconnect.
    // Returning from main exits the host and closes the native port immediately.
    Ok(())
}

fn relay_from_chrome(input: &mut impl Read, socket: &mut impl Write) -> io::Result<()> {
    while let Some(message) = read_native_frame(input)? {
        let message = String::from_utf8(message).map_err(invalid_data)?;
        let message = RawValue::from_string(message).map_err(invalid_data)?;
        write_socket_frame(socket, &Frame::Relay(RelayFrame { message }))?;
    }
    Ok(())
}

fn relay_to_chrome(socket: &mut impl Read, output: &mut impl Write) -> io::Result<()> {
    while let Some(frame) = read_socket_frame(socket)? {
        match frame {
            Frame::Relay(frame) => write_native_frame(output, frame.message.get().as_bytes())?,
            _ => {
                return Err(invalid_data(
                    "only relay frames are allowed after acceptance",
                ))
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{HostAccepted, HostRefused};
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
            let Frame::HostHello(hello) = read_socket_frame(&mut server).unwrap().unwrap() else {
                panic!("expected hello");
            };
            assert_eq!(hello.protocol, 1);
            assert_eq!(hello.extension_origin, origin());
            assert_eq!(hello.parent, parent().unwrap());
            write_socket_frame(
                &mut server,
                &Frame::HostAccepted(HostAccepted {
                    protocol: 1,
                    epoch: 23,
                }),
            )
            .unwrap();
            server
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            assert!(read_socket_frame(&mut server).unwrap().is_none());
        });
        let (socket, epoch) = establish_session(origin(), parent, || Ok(host), |_| Ok(())).unwrap();
        assert_eq!(epoch, 23);
        drop(socket);
        server.join().unwrap();
    }

    #[test]
    fn refusal_wrong_protocol_and_early_relay_never_start_relaying() {
        for reply in [
            Frame::HostRefused(HostRefused {
                reason: "wrong_origin".into(),
            }),
            Frame::HostAccepted(HostAccepted {
                protocol: 2,
                epoch: 3,
            }),
            Frame::Relay(RelayFrame {
                message: RawValue::from_string("{}".into()).unwrap(),
            }),
        ] {
            let (host, mut server) = UnixStream::pair().unwrap();
            let server = std::thread::spawn(move || {
                assert!(matches!(
                    read_socket_frame(&mut server).unwrap(),
                    Some(Frame::HostHello(_))
                ));
                write_socket_frame(&mut server, &reply).unwrap();
                let mut bytes = Vec::new();
                server.read_to_end(&mut bytes).unwrap();
                assert!(bytes.is_empty());
            });
            assert!(establish_session(origin(), parent, || Ok(host), |_| Ok(())).is_err());
            server.join().unwrap();
        }
    }

    #[test]
    fn both_relay_directions_preserve_json_value_bytes_and_frame_order() {
        let messages = [
            r#"{ "a": 1.234567890123456789, "z": [true, null], "text": "café" }"#,
            r#"["second", 18446744073709551615]"#,
        ];
        let mut chrome_wire = Vec::new();
        for message in messages {
            write_native_frame(&mut chrome_wire, message.as_bytes()).unwrap();
        }
        let mut socket_wire = Vec::new();
        relay_from_chrome(&mut Cursor::new(&chrome_wire), &mut socket_wire).unwrap();
        let mut decoded = &socket_wire[..];
        for expected in messages {
            let Some(Frame::Relay(frame)) = read_socket_frame(&mut decoded).unwrap() else {
                panic!("expected relay");
            };
            assert_eq!(frame.message.get(), expected);
        }
        assert!(decoded.is_empty());
        let mut output = Vec::new();
        relay_to_chrome(&mut &socket_wire[..], &mut output).unwrap();
        assert_eq!(output, chrome_wire);
    }

    #[test]
    fn malformed_chrome_json_and_control_frames_after_acceptance_are_refused() {
        let mut chrome_wire = Vec::new();
        write_native_frame(&mut chrome_wire, b"not json").unwrap();
        let mut socket_wire = Vec::new();
        assert!(relay_from_chrome(&mut &chrome_wire[..], &mut socket_wire).is_err());
        assert!(socket_wire.is_empty());
        write_socket_frame(
            &mut socket_wire,
            &Frame::HostAccepted(HostAccepted {
                protocol: 1,
                epoch: 3,
            }),
        )
        .unwrap();
        let mut output = Vec::new();
        assert!(relay_to_chrome(&mut &socket_wire[..], &mut output).is_err());
        assert!(output.is_empty());
    }

    #[test]
    fn relay_moves_both_directions_and_does_not_wait_for_stdin_on_server_eof() {
        let (host, mut server) = UnixStream::pair().unwrap();
        let (chrome_input, mut chrome_writer) = UnixStream::pair().unwrap();
        let (mut chrome_reader, mut chrome_output) = UnixStream::pair().unwrap();
        chrome_reader
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let relay_thread =
            std::thread::spawn(move || relay(host, chrome_input, &mut chrome_output));
        write_native_frame(&mut chrome_writer, br#"{"content":"input"}"#).unwrap();
        let Frame::Relay(frame) = read_socket_frame(&mut server).unwrap().unwrap() else {
            panic!("expected relay");
        };
        assert_eq!(frame.message.get(), r#"{"content":"input"}"#);
        write_socket_frame(
            &mut server,
            &Frame::Relay(RelayFrame {
                message: RawValue::from_string(r#"{"content":"output"}"#.into()).unwrap(),
            }),
        )
        .unwrap();
        assert_eq!(
            read_native_frame(&mut chrome_reader).unwrap().unwrap(),
            br#"{"content":"output"}"#
        );
        drop(server);
        relay_thread.join().unwrap().unwrap();
        drop(chrome_writer);
    }
}
