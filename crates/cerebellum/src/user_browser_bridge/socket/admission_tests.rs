use super::*;
use crate::user_browser_bridge::{Message, MessageBody, Route, Terminal, CANCEL_DEADLINE};
use crate::CancelHandle;
use cerebellum_bridge_protocol::{Frame, ParentAttestation, EXTENSION_ORIGIN, PROTOCOL_VERSION};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio::time::timeout;

const HANG_GUARD: Duration = Duration::from_secs(3);
const VERIFICATION_GUARD: Duration = Duration::from_millis(1500);

struct PrivateDirectory(PathBuf);

impl PrivateDirectory {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "ck-admission-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        cerebellum_core::private_fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn socket_path(&self) -> PathBuf {
        self.0.join("bridge.sock")
    }
}

impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[derive(Default)]
struct Pause {
    released: Mutex<bool>,
    ready: Condvar,
}

impl Pause {
    fn wait(&self) {
        let guard = self.released.lock().unwrap();
        drop(self.ready.wait_while(guard, |released| !*released).unwrap());
    }

    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.ready.notify_all();
    }
}

#[derive(Default)]
struct ReleaseOnDrop(Arc<Pause>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

fn hello() -> Frame {
    Frame::HostHello {
        protocol: PROTOCOL_VERSION,
        extension_origin: EXTENSION_ORIGIN.into(),
        parent: ParentAttestation {
            team_id: Some("EQHXZ8M8AV".into()),
            probe_cdhash: None,
            pid: 1,
            start_time_micros: 2,
        }
        .into(),
    }
}

async fn connect(path: &Path) -> UnixStream {
    timeout(HANG_GUARD, UnixStream::connect(path))
        .await
        .unwrap()
        .unwrap()
}

async fn accepted(path: &Path) -> (UnixStream, u64) {
    let mut stream = connect(path).await;
    write_frame(&mut stream, &hello()).await.unwrap();
    let Frame::HostAccepted { epoch, .. } = bounded_frame(&mut stream).await else {
        panic!("control peer was not accepted");
    };
    (stream, epoch)
}

async fn bounded_frame(stream: &mut UnixStream) -> Frame {
    timeout(HANG_GUARD, read_frame(stream))
        .await
        .expect("peer never replied")
        .expect("peer did not reply with a frame")
}

async fn assert_closed(stream: &mut UnixStream, budget: Duration) {
    match timeout(budget, stream.read(&mut [0; 1])).await {
        Ok(Ok(0)) => (),
        Ok(Err(error)) if error.kind() == io::ErrorKind::ConnectionReset => (),
        result => panic!("expected the connection to close without any more bytes: {result:?}"),
    }
}

async fn assert_refused(stream: &mut UnixStream, reason: &str) {
    assert_eq!(
        bounded_frame(stream).await,
        Frame::HostRefused {
            reason: reason.into(),
        }
    );
}

async fn assert_cancel_served(bridge: &UserBrowserBridge, session: &mut UnixStream) {
    async fn receive(stream: &mut UnixStream) -> Message {
        let Frame::Relay { message } = bounded_frame(stream).await else {
            panic!("expected a relay frame from the admitted connection");
        };
        serde_json::from_value(message).unwrap()
    }

    let cancel = CancelHandle::pending();
    let bridge = bridge.clone();
    let signal = cancel.clone();
    let action = tokio::spawn(async move {
        bridge
            .invoke(
                Route {
                    channel: 1,
                    epoch: 1,
                },
                serde_json::json!({"action": "click"}),
                signal,
            )
            .await
    });
    let attach = receive(session).await;
    assert!(matches!(attach.body, MessageBody::Attach { .. }));
    cancel.cancel();
    timeout(CANCEL_DEADLINE / 2, async {
        let request = receive(session).await;
        assert_eq!(request.id, attach.id);
        assert_eq!(request.epoch, attach.epoch);
        assert_eq!(request.body, MessageBody::Cancel);
        let message = serde_json::to_value(Message {
            body: MessageBody::Cancelled {
                input_dispatched: false,
                detached: true,
            },
            ..request
        })
        .unwrap();
        write_frame(session, &Frame::Relay { message })
            .await
            .unwrap();
        assert_eq!(action.await.unwrap().terminal, Terminal::Cancelled);
    })
    .await
    .expect("a blocked verification must not delay Cancel");
}

#[tokio::test]
async fn stalled_verifiers_are_bounded_and_do_not_delay_cancel_or_admit_late() {
    let directory = PrivateDirectory::new();
    let path = directory.socket_path();
    let bridge = UserBrowserBridge::new();
    let release = ReleaseOnDrop::default();
    let pause = release.0.clone();
    let (entered, mut monitors) = mpsc::unbounded_channel();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let verifier = Arc::new(move |_| {
        let retained = if count.fetch_add(1, Ordering::SeqCst) == 0 {
            None
        } else {
            let (held, observer) = std::os::unix::net::UnixStream::pair().unwrap();
            observer.set_nonblocking(true).unwrap();
            entered.send(observer).unwrap();
            pause.wait();
            Some(held.into())
        };
        Ok(PeerEvidence::Test {
            _retained: retained,
        })
    });
    let _listener = BridgeListener::bind_at(
        bridge.clone(),
        path.clone(),
        verifier,
        Arc::new(check_legacy_parent),
    )
    .unwrap();
    let (mut session, epoch) = accepted(&path).await;

    let mut refused = Vec::new();
    let mut observed_handles = Vec::new();
    for index in 0..10 {
        let mut client = connect(&path).await;
        if index < 4 {
            let observer = timeout(HANG_GUARD, monitors.recv()).await.unwrap().unwrap();
            observed_handles.push(UnixStream::from_std(observer).unwrap());
            if index == 0 {
                write_frame(&mut client, &hello()).await.unwrap();
                let ((), refusal) = tokio::join!(
                    assert_cancel_served(&bridge, &mut session),
                    timeout(
                        VERIFICATION_GUARD,
                        assert_refused(&mut client, "unsigned_peer")
                    ),
                );
                // A timed-out worker must still occupy its slot after refusal.
                refusal.expect("the stalled verifier exceeded its one-second deadline");
                assert_closed(&mut client, HANG_GUARD).await;
            } else {
                refused.push(client);
            }
        } else {
            assert_closed(&mut client, Duration::from_millis(750)).await;
        }
    }
    for client in &mut refused {
        assert_refused(client, "unsigned_peer").await;
        assert_closed(client, HANG_GUARD).await;
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        5,
        "one control and four stalled workers"
    );
    assert_eq!(bridge.connected_epoch(), Some(epoch));
    for observer in &mut observed_handles {
        assert!(
            timeout(Duration::from_millis(20), observer.read(&mut [0; 1]))
                .await
                .is_err()
        );
    }

    release.0.release();
    for observer in &mut observed_handles {
        assert_closed(observer, HANG_GUARD).await;
    }
    assert_eq!(bridge.connected_epoch(), Some(epoch));
}

#[tokio::test]
async fn stalled_parent_check_shares_verifier_capacity_and_cannot_admit_after_timeout() {
    let directory = PrivateDirectory::new();
    let path = directory.socket_path();
    let bridge = UserBrowserBridge::new();
    let release = ReleaseOnDrop::default();
    let parent_pause = release.0.clone();
    let peer_pause = release.0.clone();
    let (peer_entered, mut peers) = mpsc::unbounded_channel();
    let (parent_entered, mut parents) = mpsc::unbounded_channel();
    let peer_calls = AtomicUsize::new(0);
    let parent_calls = AtomicUsize::new(0);
    let verifier = Arc::new(move |_| {
        // The established session and the peer testing the parent check both
        // need to pass pre-hello verification.
        if peer_calls.fetch_add(1, Ordering::SeqCst) >= 2 {
            peer_entered.send(()).unwrap();
            peer_pause.wait();
        }
        Ok(PeerEvidence::Test { _retained: None })
    });
    let parent_check = Arc::new(move |evidence, parent| {
        if parent_calls.fetch_add(1, Ordering::SeqCst) != 0 {
            parent_entered.send(()).unwrap();
            parent_pause.wait();
        }
        check_legacy_parent(evidence, parent)
    });
    let _listener =
        BridgeListener::bind_at(bridge.clone(), path.clone(), verifier, parent_check).unwrap();
    let (mut session, epoch) = accepted(&path).await;
    let mut parent_client = connect(&path).await;
    write_frame(&mut parent_client, &hello()).await.unwrap();
    timeout(HANG_GUARD, parents.recv()).await.unwrap().unwrap();

    let ((), refusal, mut stalled_peers) = tokio::join!(
        assert_cancel_served(&bridge, &mut session),
        timeout(
            VERIFICATION_GUARD,
            assert_refused(&mut parent_client, "parent_attestation_invalid")
        ),
        async {
            let mut clients = Vec::new();
            for _ in 0..3 {
                clients.push(connect(&path).await);
                timeout(HANG_GUARD, peers.recv()).await.unwrap().unwrap();
            }
            let mut excess = connect(&path).await;
            assert_closed(&mut excess, Duration::from_millis(750)).await;
            clients
        },
    );
    refusal.expect("the stalled parent check exceeded its one-second deadline");
    assert_closed(&mut parent_client, HANG_GUARD).await;
    for client in &mut stalled_peers {
        assert_refused(client, "unsigned_peer").await;
    }
    release.0.release();
    assert_eq!(bridge.connected_epoch(), Some(epoch));
}

#[test]
fn subc_eof_finishes_teardown_and_runtime_drop_with_a_stalled_verifier() {
    use crate::{
        serve_until_disconnect, BrowserSurface, Flags, FrameType, HealthConfig, HealthState,
        JournalPersistence, ModuleConfig, Planes, Priority, DEFAULT_MODULE_ID,
    };
    use std::sync::mpsc::TryRecvError;
    use tokio::sync::oneshot;

    let release = ReleaseOnDrop::default();
    let pause = release.0.clone();
    let (entered_tx, entered_rx) = oneshot::channel();
    let entered_tx = Mutex::new(Some(entered_tx));
    let (verified_tx, verified_rx) = std::sync::mpsc::channel();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (eof_tx, eof_rx) = oneshot::channel();
    let (finished_tx, finished_rx) = std::sync::mpsc::channel();
    let module = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let config = ModuleConfig {
                connection_file_path: PathBuf::new(),
                module_id: DEFAULT_MODULE_ID.into(),
                health: HealthConfig::default(),
                agent_cursor: false,
                browser: BrowserSurface::NotConfigured,
            };
            let planes = Planes::with_browser_config_journaling(
                Arc::new(HealthState::with_config(config.health)),
                None,
                JournalPersistence::Isolated,
            );
            let directory = PrivateDirectory::new();
            let path = directory.socket_path();
            let listener = BridgeListener::bind_at(
                planes.user_browser.clone(),
                path.clone(),
                Arc::new(move |_| {
                    entered_tx.lock().unwrap().take().unwrap().send(()).unwrap();
                    pause.wait();
                    let _ = verified_tx.send(());
                    Ok(PeerEvidence::Test { _retained: None })
                }),
                Arc::new(check_legacy_parent),
            )
            .unwrap();
            let _client = connect(&path).await;

            let (mut daemon, module) = tokio::io::duplex(64 * 1024);
            let (mut read, write) = tokio::io::split(module);
            let peer = async move {
                let hello = subc_transport::read_frame(&mut daemon)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(hello.header.ty, FrameType::Hello);
                let ack = crate::Frame::build_with_version(
                    crate::PROTOCOL_VERSION,
                    FrameType::HelloAck,
                    Flags::new(false, Priority::Passive, false),
                    0,
                    0,
                    hello.header.corr,
                    serde_json::to_vec(&serde_json::json!({
                        "negotiated_ver": crate::PROTOCOL_VERSION,
                        "subc_ops": [],
                        "subc_capabilities": [],
                    }))
                    .unwrap(),
                )
                .unwrap();
                subc_transport::write_frame(&mut daemon, &ack)
                    .await
                    .unwrap();
                entered_rx.await.unwrap();
                ready_tx.send(()).unwrap();
                eof_rx.await.unwrap();
                drop(daemon);
            };
            // Drive the same framed EOF and shutdown teardown as the module,
            // then drop the listener before dropping the runtime as main does.
            let (result, ()) = tokio::join!(
                serve_until_disconnect(&mut read, write, &config, planes, None, None),
                peer,
            );
            result.unwrap();
            drop(listener);
            assert!(!path.exists(), "shutdown left the listener path behind");
        });
        drop(runtime);
        let _ = finished_tx.send(());
    });

    ready_rx
        .recv_timeout(HANG_GUARD)
        .expect("the verifier did not start");
    eof_tx.send(()).unwrap();
    finished_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("SUBC EOF and runtime drop must not wait for the stalled verifier");
    assert_eq!(
        verified_rx.try_recv(),
        Err(TryRecvError::Empty),
        "the verifier must still be stalled after runtime drop"
    );
    release.0.release();
    verified_rx.recv_timeout(HANG_GUARD).unwrap();
    module.join().unwrap();
}
