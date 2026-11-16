use super::*;
use crate::test_support::HANG_GUARD;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

struct FailingWriter;

impl AsyncWrite for FailingWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "writer-side sentinel",
        )))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn connection_test_config() -> ModuleConfig {
    ModuleConfig {
        connection_file_path: PathBuf::new(),
        module_id: DEFAULT_MODULE_ID.into(),
        health: HealthConfig {
            dispatch_heartbeat_stale_ms: 100,
            queue_age_stale_ms: 30_000,
            in_flight_age_stale_ms: 30_000,
        },
        agent_cursor: false,
        browser: BrowserSurface::NotConfigured,
    }
}

#[tokio::test]
async fn writer_failure_ends_connection_while_read_is_parked() {
    // A true vanished TCP peer requires a packet-filter rule that silently
    // drops traffic; closing a loopback peer would substitute EOF/RST and
    // test the wrong failure. This writer instead isolates the listener
    // contract after the kernel has diagnosed a write failure: the read peer
    // remains open and silent, so only hearing the writer can end the loop.
    let (_silent_peer, mut parked_reader) = tokio::io::duplex(1024);
    let config = connection_test_config();
    let planes = isolated_test_planes(&Arc::new(HealthState::with_config(config.health)));

    let result = tokio::time::timeout(
        HANG_GUARD,
        run_connection(&mut parked_reader, FailingWriter, &config, planes),
    )
    .await
    .expect("writer failure must end the connection while the read remains parked");
    let error = result.expect_err("the writer failure must be reported");
    assert_eq!(error.to_string(), "writer-side sentinel");
}

/// A cut daemon sends no GOODBYE and no drain; the module learns by EOF.
/// The graceful stop its browsers get hangs off the connection ending, so
/// this drives the production tail of `run` with a peer that simply goes
/// away and asserts that every session is torn down with the shutdown
/// outcome before the result is reported. `teardown_all` in isolation is
/// covered elsewhere; this is the property that EOF reaches it.
#[tokio::test]
async fn daemon_eof_reaches_browser_teardown_before_the_result_is_reported() {
    shutdown_connection(false, false).await;
}

#[tokio::test]
async fn draining_starts_browser_teardown_before_eof() {
    shutdown_connection(true, false).await;
}

#[tokio::test]
async fn a_second_draining_does_not_tear_down_twice() {
    shutdown_connection(true, true).await;
}

async fn shutdown_connection(drain: bool, twice: bool) {
    use crate::browser_session::{
        BrowserSessionTerminalOutcome, CleanupStage, OwnedBrowserProcess, ProcessControlFailure,
        SessionCleanup, SessionCleanupOutcome,
    };
    use cerebellum_core::clock::FakeClock;
    use std::sync::Mutex;

    struct ExitingProcess;
    impl OwnedBrowserProcess for ExitingProcess {
        fn generation_matches(&self) -> bool {
            true
        }
        fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
            Ok(())
        }
        fn wait_for_exit(&mut self, _: Duration) -> Result<bool, ProcessControlFailure> {
            Ok(true)
        }
        fn force_terminate(&mut self) -> Result<(), ProcessControlFailure> {
            unreachable!("graceful exit was already observed")
        }
        fn wait_until_reaped(&mut self) -> Result<(), ProcessControlFailure> {
            Ok(())
        }
    }
    struct RecordingFinalizer(Arc<Mutex<Vec<BrowserSessionTerminalOutcome>>>);
    impl SessionCleanup for RecordingFinalizer {
        fn set_terminal_outcome(&mut self, outcome: BrowserSessionTerminalOutcome) {
            self.0.lock().unwrap().push(outcome);
        }
        fn after_reap(&mut self) -> Result<SessionCleanupOutcome, CleanupStage> {
            Ok(SessionCleanupOutcome::Complete)
        }
    }

    let browser = BrowserConfig {
        executable_path: None,
        expected_identity: None,
        launch_handshake_deadline_ms: 10,
        termination_grace_period_ms: 10,
        browser_idle_timeout_ms: 100,
        browser_exit_observation_deadline_ms: 10,
        navigation_settle_deadline_ms: 10,
    };
    let config = connection_test_config();
    let planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::with_config(config.health)),
        Some(browser.clone()),
        JournalPersistence::Isolated,
    );
    let outcomes = Arc::new(Mutex::new(Vec::new()));
    let clock = FakeClock::new();
    for route in ["route-a", "route-b"] {
        let _ = planes.sessions.acquire_launch_slot(route);
        planes
            .sessions
            .establish_ready(
                route,
                cerebellum_core::identity::ProfileDisposition::Durable,
                &browser,
                &clock,
                Box::new(ExitingProcess),
                Box::new(RecordingFinalizer(Arc::clone(&outcomes))),
            )
            .expect("establish a ready session");
    }

    // The peer plays the daemon up to the point that matters: it answers
    // HELLO so the loop is serving, optionally drains while still connected,
    // then drops its end without a goodbye to exercise the EOF tail.
    let (daemon_end, module_end) = tokio::io::duplex(64 * 1024);
    let (mut module_read, module_write) = tokio::io::split(module_end);
    let observed_planes = planes.clone();
    let observed_outcomes = outcomes.clone();
    let peer = tokio::spawn(async move {
        let (mut daemon_read, mut daemon_write) = tokio::io::split(daemon_end);
        let hello = subc_transport::read_frame(&mut daemon_read)
            .await
            .expect("the module's HELLO is readable")
            .expect("the module sends HELLO first");
        assert_eq!(hello.header.ty, FrameType::Hello);
        let ack = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::HelloAck,
            Flags::new(false, Priority::Passive, false),
            0,
            0,
            hello.header.corr,
            serde_json::to_vec(&json!({
                "negotiated_ver": PROTOCOL_VERSION,
                "subc_ops": [],
                "subc_capabilities": [],
            }))
            .unwrap(),
        )
        .unwrap();
        subc_transport::write_frame(&mut daemon_write, &ack)
            .await
            .expect("HELLO_ACK is written");
        if drain {
            let notice = |deadline| {
                Frame::build_with_version(
                    PROTOCOL_VERSION,
                    FrameType::Push,
                    control_flags(),
                    0,
                    0,
                    0,
                    serde_json::to_vec(&json!({
                        "op":"module.draining", "reason":"restart", "deadline_ms":deadline
                    }))
                    .unwrap(),
                )
                .unwrap()
            };
            subc_transport::write_frame(&mut daemon_write, &notice(123))
                .await
                .unwrap();
            tokio::time::timeout(HANG_GUARD, async {
                loop {
                    if observed_outcomes.lock().unwrap().len() == 2 {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("drain must finalize browsers before EOF");
            if twice {
                subc_transport::write_frame(&mut daemon_write, &notice(456))
                    .await
                    .unwrap();
                let ping = Frame::build_with_version(
                    PROTOCOL_VERSION,
                    FrameType::Ping,
                    control_flags(),
                    0,
                    0,
                    99,
                    vec![],
                )
                .unwrap();
                subc_transport::write_frame(&mut daemon_write, &ping)
                    .await
                    .unwrap();
                let pong = subc_transport::read_frame(&mut daemon_read)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(pong.header.ty, FrameType::Pong);
                assert_eq!(observed_planes.drain_notice.get().unwrap().1, 123);
            }
        }
        // Dropping the daemon read and write halves delivers EOF to the module.
    });

    let result = tokio::time::timeout(
        HANG_GUARD,
        serve_until_disconnect(
            &mut module_read,
            module_write,
            &config,
            planes.clone(),
            Some(&browser),
            None,
        ),
    )
    .await
    .expect("EOF must end the connection");
    assert!(result.is_ok(), "a clean EOF is not an error: {result:?}");

    peer.await.expect("daemon assertions passed");
    let outcomes = outcomes.lock().unwrap();
    assert_eq!(
        outcomes.as_slice(),
        [
            BrowserSessionTerminalOutcome::ModuleShutdown,
            BrowserSessionTerminalOutcome::ModuleShutdown
        ],
        "both sessions must be torn down with the shutdown outcome by the time the \
         connection result is reported"
    );
}

#[test]
fn loop_and_writer_failures_remain_distinguishable() {
    let loop_error = reconcile_connection_results(
        Err(ModuleError::Message("loop-side sentinel".into())),
        Ok(Err(ModuleError::Message("writer-side sentinel".into()))),
    )
    .expect_err("a loop failure must remain the primary diagnosis");
    assert_eq!(loop_error.to_string(), "loop-side sentinel");

    let writer_error = reconcile_connection_results(
        Ok(()),
        Ok(Err(ModuleError::Message("writer-side sentinel".into()))),
    )
    .expect_err("a writer failure must be reported when the loop was healthy");
    assert_eq!(writer_error.to_string(), "writer-side sentinel");
}

#[tokio::test]
async fn tcp_keepalive_is_verified_on_the_connected_socket() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
    let client = client.unwrap();
    let (_server, _) = accepted.unwrap();

    configure_tcp_keepalive(&client).unwrap();

    let socket = SockRef::from(&client);
    assert!(socket.keepalive().unwrap());
    // socket2 exposes the idle and interval getters only on Unix.
    #[cfg(unix)]
    {
        assert_eq!(socket.tcp_keepalive_time().unwrap(), TCP_KEEPALIVE_IDLE);
        assert_eq!(
            socket.tcp_keepalive_interval().unwrap(),
            TCP_KEEPALIVE_INTERVAL
        );
    }
    assert_eq!(
        socket.tcp_keepalive_retries().unwrap(),
        TCP_KEEPALIVE_RETRIES
    );
}
