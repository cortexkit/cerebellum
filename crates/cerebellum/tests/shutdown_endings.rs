//! How the module process ends, observed from outside it.
//!
//! The in-process connection tests call the serving loop directly and never
//! reach the code that turns an ending into an exit status. A module that
//! re-raised SIGTERM on every ending, or exited 0 on SIGTERM, would pass them.
//! Only a separate process that runs the module's own ending can tell those
//! apart, so each test here starts one: this test binary re-executed with a
//! filter that selects `module_child_entry`, which runs the module through
//! `run_entry_prepared_for_test` (the same run and ending as `run_entry`) with
//! two fake browser sessions to tear down.
//!
//! The parent plays the daemon: it publishes a connection file, authenticates
//! the module, answers HELLO, and then either keeps the socket open or closes
//! it. Each fake session writes a line to a marker file when its browser is
//! asked to close and another when its after-reap cleanup (the step that
//! releases profile custody) runs, so the parent can see the teardown happen.
#![cfg(unix)]

use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cerebellum::browser_session::{
    BrowserSessionLauncher, BrowserSessionTerminalOutcome, CleanupStage, LaunchedBrowser,
    OwnedBrowserProcess, ProcessControlFailure, SessionCleanup, SessionCleanupOutcome,
};
use cerebellum::BrowserConfig;
use cerebellum_core::identity::{AcceptedBindFacts, ProfileDisposition};
use serde_json::{json, Value};
use subc_protocol::{Flags, Frame, FrameType, Priority, PROTOCOL_VERSION};
use subc_transport::connection_file::{self, ConnectionInfo, Endpoint};
use tokio::net::{TcpListener, TcpStream};

/// Set only in the child: the connection file it should connect with.
const CHILD_CONNECTION_ENV: &str = "CEREBELLUM_ENDING_CHILD_CONNECTION";
/// Where the child's fake sessions write their teardown markers.
const CHILD_MARKERS_ENV: &str = "CEREBELLUM_ENDING_CHILD_MARKERS";
/// How long each fake browser takes to exit after it is asked to close.
const CHILD_CLOSE_MS_ENV: &str = "CEREBELLUM_ENDING_CHILD_CLOSE_MS";

const ROUTES: [&str; 2] = ["route-a", "route-b"];

/// Generous, because it only decides how long a broken child takes to fail.
const CHILD_DEADLINE: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// The child side.
// ---------------------------------------------------------------------------

/// The module process the other tests start. In an ordinary test run the
/// variable is absent and this returns at once.
#[test]
fn module_child_entry() {
    let Some(connection) = std::env::var_os(CHILD_CONNECTION_ENV) else {
        return;
    };
    let markers = PathBuf::from(std::env::var_os(CHILD_MARKERS_ENV).expect("marker path"));
    let close_ms = std::env::var(CHILD_CLOSE_MS_ENV)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let browser = child_browser_config();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("child runtime");
    let result = runtime.block_on(cerebellum::run_entry_prepared_for_test(
        PathBuf::from(connection),
        browser.clone(),
        move |planes| {
            // Present so the module does not open the production launch
            // service, which would touch the real launch journal.
            planes.launch_service = Some(Arc::new(RefusingLauncher));
            for route in ROUTES {
                let _ = planes.sessions.acquire_launch_slot(route);
                planes
                    .sessions
                    .establish_ready(
                        route,
                        ProfileDisposition::Durable,
                        &browser,
                        planes.lease_clock.as_ref(),
                        Box::new(MarkerProcess {
                            route,
                            markers: markers.clone(),
                            close_ms,
                        }),
                        Box::new(MarkerCleanup {
                            route,
                            markers: markers.clone(),
                            outcome: None,
                        }),
                    )
                    .expect("seed a ready session");
            }
        },
    ));
    // The same mapping `main` gets from returning this result: 0 for Ok, 1 for
    // Err. A SIGTERM ending never gets here, because the process re-raises the
    // signal inside `run_entry_prepared_for_test`.
    if let Err(error) = &result {
        eprintln!("module ended with an error: {error}");
    }
    std::process::exit(if result.is_ok() { 0 } else { 1 });
}

fn child_browser_config() -> BrowserConfig {
    BrowserConfig {
        executable_path: None,
        expected_identity: None,
        launch_handshake_deadline_ms: 1_000,
        termination_grace_period_ms: 10_000,
        // Long enough that idle expiry never tears a session down first.
        browser_idle_timeout_ms: 600_000,
        browser_exit_observation_deadline_ms: 1_000,
        navigation_settle_deadline_ms: 1_000,
    }
}

struct RefusingLauncher;

impl BrowserSessionLauncher for RefusingLauncher {
    fn launch(&self, _: &AcceptedBindFacts, _: &str) -> Result<LaunchedBrowser, Value> {
        Err(json!({"outcome": "launch_refused_in_test"}))
    }
}

fn mark(markers: &Path, line: &str) {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(markers)
        .expect("open marker file");
    // One write per line, so lines from concurrent sessions never interleave.
    file.write_all(format!("{line}\n").as_bytes())
        .expect("write marker");
}

struct MarkerProcess {
    route: &'static str,
    markers: PathBuf,
    close_ms: u64,
}

impl OwnedBrowserProcess for MarkerProcess {
    fn generation_matches(&self) -> bool {
        true
    }

    fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
        mark(&self.markers, &format!("closing {}", self.route));
        Ok(())
    }

    fn wait_for_exit(&mut self, _: Duration) -> Result<bool, ProcessControlFailure> {
        std::thread::sleep(Duration::from_millis(self.close_ms));
        Ok(true)
    }

    fn force_terminate(&mut self) -> Result<(), ProcessControlFailure> {
        Ok(())
    }

    fn wait_until_reaped(&mut self) -> Result<(), ProcessControlFailure> {
        Ok(())
    }
}

struct MarkerCleanup {
    route: &'static str,
    markers: PathBuf,
    outcome: Option<BrowserSessionTerminalOutcome>,
}

impl SessionCleanup for MarkerCleanup {
    fn set_terminal_outcome(&mut self, outcome: BrowserSessionTerminalOutcome) {
        self.outcome = Some(outcome);
    }

    fn after_reap(&mut self) -> Result<SessionCleanupOutcome, CleanupStage> {
        let outcome = self
            .outcome
            .map_or("none", BrowserSessionTerminalOutcome::as_str);
        mark(&self.markers, &format!("released {} {outcome}", self.route));
        Ok(SessionCleanupOutcome::Complete)
    }
}

// ---------------------------------------------------------------------------
// The parent side: a fake daemon and the child it serves.
// ---------------------------------------------------------------------------

struct Harness {
    directory: PathBuf,
    markers: PathBuf,
    listener: TcpListener,
    key: Vec<u8>,
    daemon_id: [u8; connection_file::DAEMON_ID_LEN],
    child: tokio::process::Child,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

impl Harness {
    async fn start(close_ms: u64) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after the epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("cerebellum-endings-{nonce}"));
        let home = directory.join("home");
        std::fs::create_dir_all(&home).expect("create isolated home");
        let markers = directory.join("markers.txt");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let key = connection_file::generate_key().expect("key");
        let daemon_id = connection_file::generate_daemon_id().expect("daemon id");
        let connection_path = directory.join("subc-connection.json");
        connection_file::write_atomic(
            &connection_path,
            &ConnectionInfo {
                schema: connection_file::SCHEMA_VERSION,
                wire_version: None,
                endpoints: vec![Endpoint {
                    host: "127.0.0.1".into(),
                    port: listener.local_addr().expect("address").port(),
                }],
                key: key.clone(),
                daemon_id,
                pid: std::process::id(),
                daemon_ver: "test".into(),
            },
        )
        .expect("write connection file");
        let stderr = std::fs::File::create(directory.join("child.stderr")).expect("stderr file");
        let child = tokio::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "module_child_entry",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_CONNECTION_ENV, &connection_path)
            .env(CHILD_MARKERS_ENV, &markers)
            .env(CHILD_CLOSE_MS_ENV, close_ms.to_string())
            // The module resolves its data and config homes XDG first; pin all
            // of them so it never writes into the real ones.
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("XDG_DATA_HOME", home.join(".local").join("share"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr)
            .kill_on_drop(true)
            .spawn()
            .expect("spawn the module child");
        Self {
            directory,
            markers,
            listener,
            key,
            daemon_id,
            child,
        }
    }

    /// Accept the module, authenticate it, and answer its HELLO, leaving the
    /// connection open and the module serving.
    async fn accept_and_register(&self) -> TcpStream {
        let (mut stream, _) = tokio::time::timeout(CHILD_DEADLINE, self.listener.accept())
            .await
            .expect("the module connects")
            .expect("accept");
        subc_transport::authenticate_server(
            &mut stream,
            &self.key,
            &self.daemon_id,
            "test",
            Duration::from_secs(10),
        )
        .await
        .expect("the module authenticates");
        let hello = subc_transport::read_frame(&mut stream)
            .await
            .expect("HELLO is readable")
            .expect("the module sends HELLO");
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
            .expect("HELLO_ACK body"),
        )
        .expect("HELLO_ACK frame");
        subc_transport::write_frame(&mut stream, &ack)
            .await
            .expect("HELLO_ACK is written");
        // The sessions are seeded before HELLO is sent, so they exist now.
        // A short pause lets the module enter its serving loop.
        tokio::time::sleep(Duration::from_millis(200)).await;
        stream
    }

    fn sigterm(&self) {
        let pid = self.child.id().expect("the child is still running");
        let status = std::process::Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .expect("run kill");
        assert!(status.success(), "kill -TERM {pid} failed");
    }

    async fn wait_for_exit(&mut self) -> ExitStatus {
        match tokio::time::timeout(CHILD_DEADLINE, self.child.wait()).await {
            Ok(status) => status.expect("wait for the child"),
            Err(_) => panic!(
                "the module child did not exit within {CHILD_DEADLINE:?}; stderr: {}",
                self.stderr()
            ),
        }
    }

    async fn wait_for_marker(&self, line: &str) {
        let started = Instant::now();
        while !self.marker_lines().iter().any(|marker| marker == line) {
            assert!(
                started.elapsed() < CHILD_DEADLINE,
                "no `{line}` marker; markers: {:?}; stderr: {}",
                self.marker_lines(),
                self.stderr()
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn marker_lines(&self) -> Vec<String> {
        std::fs::read_to_string(&self.markers)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn stderr(&self) -> String {
        std::fs::read_to_string(self.directory.join("child.stderr")).unwrap_or_default()
    }

    /// Every session was closed and released exactly once, as a shutdown.
    fn assert_torn_down_once(&self) {
        let markers = self.marker_lines();
        for route in ROUTES {
            for expected in [
                format!("closing {route}"),
                format!("released {route} module_shutdown"),
            ] {
                let count = markers.iter().filter(|line| **line == expected).count();
                assert_eq!(
                    count,
                    1,
                    "`{expected}` seen {count} times; markers: {markers:?}; stderr: {}",
                    self.stderr()
                );
            }
        }
    }
}

fn describe(status: ExitStatus) -> String {
    match (status.code(), status.signal()) {
        (Some(code), _) => format!("exit {code}"),
        (_, Some(signal)) => format!("signal {signal}"),
        _ => format!("{status:?}"),
    }
}

/// SIGTERM must both run the teardown and end the process by signal 15.
/// Either half alone matches a broken module: one with no handler dies by
/// signal 15 with no teardown, and one whose handler exits 0 tears down but is
/// then read by its supervisor as a deliberate stop and never respawned.
#[tokio::test]
async fn sigterm_tears_down_then_dies_by_signal_15() {
    let mut harness = Harness::start(0).await;
    let _connection = harness.accept_and_register().await;

    harness.sigterm();
    let status = harness.wait_for_exit().await;

    assert_eq!(
        status.signal(),
        Some(15),
        "SIGTERM must end the module by signal 15, not {}; stderr: {}",
        describe(status),
        harness.stderr()
    );
    harness.assert_torn_down_once();
}

/// The daemon closing the connection is a normal ending: the teardown runs and
/// the process exits 0, with no signal.
#[tokio::test]
async fn connection_close_tears_down_then_exits_zero() {
    let mut harness = Harness::start(0).await;
    let connection = harness.accept_and_register().await;

    drop(connection);
    let status = harness.wait_for_exit().await;

    assert_eq!(
        status.code(),
        Some(0),
        "a closed connection must end the module with exit 0, not {}; stderr: {}",
        describe(status),
        harness.stderr()
    );
    harness.assert_torn_down_once();
}

/// SIGTERM arriving while the teardown the connection ending started is still
/// running joins that teardown rather than starting another, and the process
/// still dies by signal 15.
#[tokio::test]
async fn sigterm_during_the_connection_teardown_joins_it_and_dies_by_signal_15() {
    // Each browser takes this long to exit, which holds the teardown open long
    // enough to deliver SIGTERM in the middle of it.
    let mut harness = Harness::start(1_500).await;
    let connection = harness.accept_and_register().await;

    drop(connection);
    harness.wait_for_marker("closing route-a").await;
    harness.wait_for_marker("closing route-b").await;
    let released_before_sigterm = harness
        .marker_lines()
        .iter()
        .filter(|line| line.starts_with("released"))
        .count();
    harness.sigterm();
    let status = harness.wait_for_exit().await;

    assert_eq!(
        released_before_sigterm, 0,
        "SIGTERM must land while the teardown is still running for this test to mean anything"
    );
    assert_eq!(
        status.signal(),
        Some(15),
        "SIGTERM during the teardown must still end the module by signal 15, not {}; stderr: {}",
        describe(status),
        harness.stderr()
    );
    harness.assert_torn_down_once();
}
