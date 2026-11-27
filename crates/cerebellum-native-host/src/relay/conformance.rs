use super::*;
use cerebellum_bridge_protocol::{encode, ParentAttestation, EXTENSION_ORIGIN, MAX_FRAME_BYTES};
use serde_json::value::RawValue;
use std::io::Cursor;

fn parent() -> io::Result<ParentAttestation> {
    Ok(ParentAttestation {
        team_id: Some("EQHXZ8M8AV".into()),
        probe_cdhash: None,
        pid: 12,
        start_time_micros: 34,
    })
}

// Allow for timer rounding, frame encoding and scheduling on loaded runners.
const TEST_LIMIT: Duration = Duration::from_secs(HANDSHAKE_TIMEOUT.as_secs() + 2);

fn check_stalled_handshake<T: Transport>((host, mut peer): (T, T), prefilled: Option<usize>) {
    // Darwin doesn't let the peer set a timeout after the host disconnects.
    peer.set_read_timeout(Some(TEST_LIMIT)).unwrap();
    let (result, done) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = result.send(establish_session(
            EXTENSION_ORIGIN.into(),
            parent,
            || Ok(host),
            |_| Ok(()),
        ));
    });
    // Keep the other end connected without reading or replying. The watchdog
    // fails the test if the blocked I/O never wakes; dropping the peer unblocks it.
    let Err(error) = done.recv_timeout(TEST_LIMIT).expect("handshake timed out") else {
        panic!("stalled handshake was accepted");
    };
    assert!(
        matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ),
        "{error}"
    );

    let mut sent = Vec::new();
    peer.read_to_end(&mut sent).unwrap();
    if let Some(prefilled) = prefilled {
        assert_eq!(sent, vec![0; prefilled], "handshake write did not stall");
    } else {
        assert!(matches!(
            read_socket_control_frame(&mut sent.as_slice()).unwrap(),
            Frame::HostHello { .. }
        ));
    }
}

fn check_handshake_bound<T: Transport>((host, mut peer): (T, T)) {
    let prefix = (MAX_FRAME_BYTES as u32 + 1).to_be_bytes();
    peer.write_all(&prefix).unwrap();
    let Err(error) = establish_session(EXTENSION_ORIGIN.into(), parent, || Ok(host), |_| Ok(()))
    else {
        panic!("oversized handshake reply was accepted");
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

struct OpenChromeInput(mpsc::Receiver<()>);

impl Read for OpenChromeInput {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        let _ = self.0.recv();
        Ok(0)
    }
}

fn check_accepted_relay<T: Transport>((host, mut peer): (T, T)) {
    let (keep_chrome_open, chrome_input) = mpsc::channel();
    let (result, done) = mpsc::sync_channel(1);
    let message =
        RawValue::from_string(r#"{ "number": 1.234567890123456789, "text": "café" }"#.into())
            .unwrap();
    let body = raw_relay_body(&message).unwrap();
    let mut chrome_wire = Vec::new();
    write_native_frame(&mut chrome_wire, &body).unwrap();

    std::thread::spawn(move || {
        let (host, epoch) =
            establish_session(EXTENSION_ORIGIN.into(), parent, || Ok(host), |_| Ok(())).unwrap();
        let mut output = Vec::new();
        let end = relay(
            host,
            epoch,
            Cursor::new(chrome_wire).chain(OpenChromeInput(chrome_input)),
            &mut output,
        );
        let _ = result.send((end, output));
    });

    peer.set_read_timeout(Some(TEST_LIMIT)).unwrap();
    peer.set_write_timeout(TEST_LIMIT).unwrap();
    assert_eq!(
        read_socket_control_frame(&mut peer).unwrap(),
        Frame::HostHello {
            protocol: PROTOCOL_VERSION,
            extension_origin: EXTENSION_ORIGIN.into(),
            parent: parent().unwrap().into(),
        }
    );
    let accepted = Frame::HostAccepted {
        protocol: PROTOCOL_VERSION,
        epoch: 23,
    };
    write_socket_control_frame(&mut peer, &accepted).unwrap();
    let expected = cerebellum_bridge_protocol::encode_raw_relay(&message).unwrap();
    let mut sent = vec![0; expected.len()];
    peer.read_exact(&mut sent).unwrap();
    assert_eq!(sent, expected);

    // The handshake deadline must no longer end the session after acceptance.
    assert!(matches!(
        done.recv_timeout(TEST_LIMIT),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    write_raw_relay(&mut peer, &message).unwrap();
    drop(peer);
    let (end, output) = done
        .recv_timeout(TEST_LIMIT)
        .expect("relay hung on disconnect");
    assert!(matches!(end, RelayEnd::SocketClosed), "{end}");
    // Chrome stdin stayed open through relay termination.
    drop(keep_chrome_open);

    let mut output = &output[..];
    assert_eq!(
        read_native_frame(&mut output).unwrap().unwrap(),
        encode(&accepted).unwrap()[4..]
    );
    assert_eq!(read_native_frame(&mut output).unwrap().unwrap(), body);
    assert!(output.is_empty());
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn stalled_handshake_read_times_out() {
        check_stalled_handshake(UnixStream::pair().unwrap(), None);
    }

    #[test]
    fn stalled_handshake_write_times_out() {
        let (mut host, peer) = UnixStream::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        // A filled send buffer stalls the first handshake write, not a later
        // write_all iteration after a successful partial write.
        let mut prefilled = 0;
        for chunk in [&[0; 4096][..], &[0][..]] {
            loop {
                match host.write(chunk) {
                    Ok(n) if n > 0 => prefilled += n,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    result => panic!("could not fill the send buffer: {result:?}"),
                }
            }
        }
        host.set_nonblocking(false).unwrap();
        check_stalled_handshake((host, peer), Some(prefilled));
    }

    #[test]
    fn handshake_rejects_an_oversized_frame() {
        check_handshake_bound(UnixStream::pair().unwrap());
    }

    #[test]
    fn accepted_relay_stays_open_preserves_bytes_and_ends_on_disconnect() {
        check_accepted_relay(UnixStream::pair().unwrap());
    }
}
