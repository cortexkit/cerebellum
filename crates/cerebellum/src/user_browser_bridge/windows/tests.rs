use super::*;
use crate::user_browser_bridge::admission::PeerEvidence;
use crate::user_browser_bridge::session::{read_frame, write_frame};
use cerebellum_bridge_protocol::peer_trailer::{parse_public_key, TEST_PEER_PUBLIC_KEY_HEX};
use cerebellum_bridge_protocol::{
    AttestationV1, Frame, PlatformParentAttestation, WindowsProcess, EXTENSION_ORIGIN,
    PROTOCOL_VERSION,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tokio::sync::{mpsc, Barrier};
use tokio::time::{sleep, timeout};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const ERROR_PIPE_BUSY: i32 = 231;

fn fixture_endpoint() -> PipeEndpoint {
    static SERIAL: AtomicUsize = AtomicUsize::new(0);
    let process = std::process::id();
    let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
    let time = system_time_100ns();
    PipeEndpoint::private(
        format!(r"\\.\pipe\ck-bridge-test-{process}-{time}-{serial}"),
        current_user_sid().unwrap(),
    )
}

fn open(name: &str) -> io::Result<NamedPipeClient> {
    ClientOptions::new().open(name)
}

async fn retry_busy(name: &str) -> NamedPipeClient {
    timeout(TEST_TIMEOUT, async {
        loop {
            match open(name) {
                Ok(client) => return client,
                Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                    sleep(Duration::from_millis(5)).await;
                }
                Err(error) => panic!("pipe was neither listening nor busy: {error}"),
            }
        }
    })
    .await
    .expect("pipe stayed busy")
}

fn attestation() -> HostParentAttestation {
    PlatformParentAttestation::Windows {
        v: AttestationV1,
        chrome: WindowsProcess {
            pid: 13,
            creation_100ns: 21,
        },
        launcher: WindowsProcess {
            pid: 34,
            creation_100ns: 55,
        },
    }
    .into()
}

fn injected() -> Admission {
    Admission::injected(
        Arc::new(|PeerIdentity::Windows(_)| Ok(PeerEvidence::Test {})),
        Arc::new(|_, parent| {
            if parent == attestation() {
                Ok(())
            } else {
                Err(Reason::ParentAttestationInvalid)
            }
        }),
    )
}

async fn reply(client: &mut NamedPipeClient) -> Frame {
    timeout(TEST_TIMEOUT, read_frame(client))
        .await
        .expect("listener did not send a reply")
        .unwrap()
}

#[test]
fn unbound_gate_never_builds_endpoint() {
    let result = bind_with(UserBrowserBridge::new(), None, None, || {
        panic!("unbound gate must not resolve or create the endpoint")
    });
    let Err(error) = result else {
        panic!("unbound gate admitted a listener");
    };
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    assert_eq!(
        error.to_string(),
        "native messaging is not enabled in this build"
    );
}

#[tokio::test]
async fn occupied_pipe_name_fails_closed() {
    let endpoint = fixture_endpoint();
    let name = endpoint.name.clone();
    let occupier = endpoint.create(true).unwrap();
    let Err(error) = PipeListener::bind(UserBrowserBridge::new(), endpoint, injected()) else {
        panic!("bound an already occupied name");
    };
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    let client = open(&name).unwrap();
    timeout(TEST_TIMEOUT, occupier.connect())
        .await
        .unwrap()
        .unwrap();
    drop(client);
}

#[tokio::test]
async fn replacement_is_open_before_the_connected_instance_is_handed_off() {
    let endpoint = fixture_endpoint();
    let name = endpoint.name.clone();
    let first = endpoint.create(true).unwrap();
    let _first_client = open(&name).unwrap();
    let (next, mut opened) = mpsc::unbounded_channel();
    let mut probe = Some(next);
    let accept = tokio::spawn(accept_peers(first, endpoint, move |stream, _| {
        // The old instance is still connected, so this open can only succeed
        // on the replacement instance.
        if let Some(next) = probe.take() {
            next.send(open(&name)).unwrap();
        }
        async move { drop(stream) }
    }));
    let _second_client = timeout(TEST_TIMEOUT, opened.recv())
        .await
        .unwrap()
        .unwrap()
        .expect("replacement was not listening at handoff");
    accept.abort();
    assert!(accept.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn ten_concurrent_busy_clients_all_reach_the_listener() {
    let endpoint = fixture_endpoint();
    let name = endpoint.name.clone();
    let first = endpoint.create(true).unwrap();
    let mut blocker = open(&name).unwrap();
    blocker.write_u8(255).await.unwrap();
    let ready = Arc::new(Barrier::new(11));
    let mut clients = JoinSet::new();
    for value in 0..10 {
        let ready = ready.clone();
        let name = name.clone();
        clients.spawn(async move {
            // The first instance is occupied and the accept loop has not yet
            // started. All ten clients must take the busy-retry path.
            assert_eq!(
                open(&name).unwrap_err().raw_os_error(),
                Some(ERROR_PIPE_BUSY)
            );
            ready.wait().await;
            let mut client = retry_busy(&name).await;
            client.write_u8(value).await.unwrap();
            client
        });
    }
    timeout(TEST_TIMEOUT, ready.wait()).await.unwrap();
    let sid = endpoint.user.clone();
    let (received, mut values) = mpsc::unbounded_channel();
    let accept = tokio::spawn(accept_peers(first, endpoint, move |mut stream, _| {
        let err = create_named_pipe_instance(&name, &[&sid], true, true).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let received = received.clone();
        async move { received.send(stream.read_u8().await.unwrap()).unwrap() }
    }));
    timeout(TEST_TIMEOUT, async {
        let mut actual = Vec::new();
        for _ in 0..11 {
            actual.push(values.recv().await.unwrap());
        }
        actual.sort_unstable();
        assert_eq!(actual, (0..10).chain([255]).collect::<Vec<_>>());
        while let Some(result) = clients.join_next().await {
            result.unwrap();
        }
    })
    .await
    .unwrap();
    accept.abort();
    assert!(accept.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn client_created_after_timestamp_is_refused() {
    let endpoint = fixture_endpoint();
    let stream = endpoint.create(true).unwrap();
    let _client = open(&endpoint.name).unwrap();
    timeout(TEST_TIMEOUT, stream.connect())
        .await
        .unwrap()
        .unwrap();
    assert!(observe_peer(&stream, system_time_100ns()).is_ok());
    assert!(matches!(
        observe_peer(&stream, 0),
        Err(Reason::UnsignedPeer)
    ));
}

#[tokio::test]
async fn unsigned_client_is_refused_before_sending_hello() {
    let bridge = UserBrowserBridge::new();
    let endpoint = fixture_endpoint();
    let name = endpoint.name.clone();
    let key = parse_public_key(TEST_PEER_PUBLIC_KEY_HEX).unwrap();
    let _listener = PipeListener::bind(bridge.clone(), endpoint, Admission::windows(key)).unwrap();
    let mut client = open(&name).unwrap();
    assert_eq!(
        reply(&mut client).await,
        Frame::HostRefused {
            reason: "unsigned_peer".into()
        }
    );
    assert_eq!(bridge.connected_epoch(), None);
}

#[tokio::test]
async fn named_pipe_uses_common_frame_admission_and_session_shutdown() {
    let bridge = UserBrowserBridge::new();
    let endpoint = fixture_endpoint();
    let name = endpoint.name.clone();
    let listener = PipeListener::bind(bridge.clone(), endpoint, injected()).unwrap();

    let mut invalid = retry_busy(&name).await;
    invalid.write_all(b"\0\0\0\x01{").await.unwrap();
    assert_eq!(
        reply(&mut invalid).await,
        Frame::HostRefused {
            reason: "protocol_error".into()
        }
    );
    assert_eq!(bridge.connected_epoch(), None);

    let hello = |protocol, origin: &str, parent| Frame::HostHello {
        protocol,
        extension_origin: origin.into(),
        parent,
    };
    let legacy = cerebellum_bridge_protocol::ParentAttestation {
        team_id: Some("EQHXZ8M8AV".into()),
        probe_cdhash: None,
        pid: 12,
        start_time_micros: 34,
    };
    for (frame, reason) in [
        (
            hello(2, EXTENSION_ORIGIN, attestation()),
            "protocol_mismatch",
        ),
        (
            hello(PROTOCOL_VERSION, "chrome-extension://other/", attestation()),
            "extension_origin_mismatch",
        ),
        (
            hello(PROTOCOL_VERSION, EXTENSION_ORIGIN, legacy.into()),
            "parent_attestation_invalid",
        ),
    ] {
        let mut client = retry_busy(&name).await;
        write_frame(&mut client, &frame).await.unwrap();
        assert_eq!(
            reply(&mut client).await,
            Frame::HostRefused {
                reason: reason.into()
            }
        );
        assert_eq!(bridge.connected_epoch(), None);
    }

    let mut client = retry_busy(&name).await;
    write_frame(
        &mut client,
        &hello(PROTOCOL_VERSION, EXTENSION_ORIGIN, attestation()),
    )
    .await
    .unwrap();
    let Frame::HostAccepted {
        protocol: PROTOCOL_VERSION,
        epoch,
    } = reply(&mut client).await
    else {
        panic!("valid fixture hello did not start a session");
    };
    assert_eq!(bridge.connected_epoch(), Some(epoch));
    assert!(timeout(Duration::from_millis(30), client.read_u8())
        .await
        .is_err());
    drop(client);
    timeout(TEST_TIMEOUT, async {
        while bridge.connected_epoch().is_some() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("disconnect did not end the session");
    drop(listener);
}

#[tokio::test]
#[ignore = "requires authenticated loopback SMB access to named pipes"]
async fn remote_client_refused_with_reachable_control() {
    let endpoint = fixture_endpoint();
    let control = fixture_endpoint();
    let _listener = endpoint.create(true).unwrap();
    let _control =
        create_named_pipe_instance(&control.name, &[&control.user], true, false).unwrap();
    let remote = |name: &str| name.replacen(r"\\.", r"\\127.0.0.1", 1);
    let _remote_control =
        open(&remote(&control.name)).expect("loopback SMB control is not reachable");
    let error = open(&remote(&endpoint.name)).expect_err("listener accepted a remote client");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    let _local_client = open(&endpoint.name).expect("same-user local control is not reachable");
}
