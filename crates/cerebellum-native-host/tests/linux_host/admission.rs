use super::*;
use cerebellum_bridge_protocol::peer_trailer::TEST_PEER_PUBLIC_KEY_HEX;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::process::{Child, Stdio};
use std::thread;
use std::time::Instant;

const STEP_1: &str = "step-1";
const STEP_2: &str = "step-2";
const PARENT_TEST: &str = "admission::spawn_host_from_signed_test_parent";

#[test]
#[ignore = "fixture entry point; invoked from a signed copy of the test binary"]
fn spawn_host_from_signed_test_parent() {
    let output = Command::new(host_binary())
        .args([EXTENSION_ORIGIN, "--parent-window=1234"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
}

#[test]
#[ignore = "requires the open CI gate and a peer-trailer binary beside the host"]
fn linux_host_stalled_step_1_exits_without_connecting() {
    let fixture = Fixture::new();
    fixture.run(Some(STEP_1), STEP_1, None);
    fixture.assert_no_connection();
}

#[test]
#[ignore = "requires the open CI gate and a peer-trailer binary beside the host"]
fn linux_host_stalled_step_2_exits_without_a_hello() {
    let fixture = Fixture::new();
    fixture.run(Some(STEP_2), STEP_2, Some(&fixture.endpoint));
    fixture.assert_connection_without_bytes();
}

#[test]
#[ignore = "requires the open CI gate and a peer-trailer binary beside the host"]
fn linux_host_refuses_insecure_modes_and_relative_overrides_before_connecting() {
    let fixture = Fixture::new();
    let directory = fixture.endpoint.parent().unwrap();
    for (path, wrong, correct) in [(directory, 0o755, 0o700), (&fixture.endpoint, 0o666, 0o600)] {
        fs::set_permissions(path, fs::Permissions::from_mode(wrong)).unwrap();
        fixture.run(None, STEP_1, None);
        fixture.assert_no_connection();
        fs::set_permissions(path, fs::Permissions::from_mode(correct)).unwrap();
    }
    let relative = fixture
        .endpoint
        .strip_prefix(fixture.scratch.path())
        .unwrap();
    fixture.run(None, STEP_1, Some(relative));
    fixture.assert_no_connection();

    // The same parent and endpoint reach step 2 when the pre-connect checks
    // pass. The listener is unsigned, so verification still forbids a hello.
    fixture.run(None, STEP_2, None);
    fixture.assert_connection_without_bytes();
}

struct Fixture {
    scratch: Scratch,
    endpoint: PathBuf,
    listener: UnixListener,
    signed_parent: PathBuf,
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Fixture {
    fn new() -> Self {
        cerebellum_native_host::check_build_gate().expect("build the host with the open CI gate");
        cerebellum_bridge_protocol::linux::probe_kernel().unwrap();
        let scratch = Scratch::new();
        let endpoint = scratch
            .path()
            .join("cortexkit/run/cerebellum/user-browser.sock");
        cerebellum_core::private_fs::create_dir_all(endpoint.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&endpoint).unwrap();
        fs::set_permissions(&endpoint, fs::Permissions::from_mode(0o600)).unwrap();
        listener.set_nonblocking(true).unwrap();

        let signed_parent = scratch.path().join("signed-test-parent");
        fs::copy(std::env::current_exe().unwrap(), &signed_parent).unwrap();
        let target = match (std::env::consts::ARCH, cfg!(target_env = "musl")) {
            ("x86_64", false) => "x86_64-unknown-linux-gnu",
            ("aarch64", false) => "aarch64-unknown-linux-gnu",
            ("x86_64", true) => "x86_64-unknown-linux-musl",
            ("aarch64", true) => "aarch64-unknown-linux-musl",
            _ => panic!("no bridge test target triple for this host"),
        };
        let signed = Command::new(host_binary().with_file_name("peer-trailer"))
            .args(["sign", "--test-key"])
            .arg(&signed_parent)
            .args(["test-parent", target, env!("CARGO_PKG_VERSION")])
            .env(
                "CEREBELLUM_BRIDGE_PEER_PUBLIC_KEY",
                TEST_PEER_PUBLIC_KEY_HEX,
            )
            .output()
            .expect("build cerebellum-bridge-protocol's peer-trailer binary in the same profile");
        assert!(
            signed.status.success(),
            "could not sign fixture: {signed:?}"
        );

        Self {
            scratch,
            endpoint,
            listener,
            signed_parent,
        }
    }

    fn run(&self, pause: Option<&str>, last_step: &str, override_path: Option<&Path>) {
        let root = self.scratch.path();
        let checkpoint = root.join("checkpoint");
        if checkpoint.exists() {
            fs::remove_file(&checkpoint).unwrap();
        }
        let mut command = Command::new(&self.signed_parent);
        command
            .args(["--exact", PARENT_TEST, "--ignored", "--nocapture"])
            .current_dir(root)
            .env("HOME", root)
            .env("XDG_DATA_HOME", root)
            .env("CK_BRIDGE_TEST_CHECKPOINT", &checkpoint)
            .stdout(Stdio::null());
        match pause {
            Some(step) => command.env("CK_BRIDGE_TEST_PAUSE", step),
            None => command.env_remove("CK_BRIDGE_TEST_PAUSE"),
        };
        match override_path {
            Some(path) => command.env("CK_BRIDGE_TEST_SOCKET", path),
            None => command.env_remove("CK_BRIDGE_TEST_SOCKET"),
        };
        let mut parent = ChildGuard(command.spawn().unwrap());
        let start_deadline = Instant::now() + Duration::from_millis(2500);
        let observed = wait_until(start_deadline, || {
            if fs::read_to_string(&checkpoint).is_ok_and(|step| step.trim() == last_step) {
                return Some(Instant::now());
            }
            assert!(
                parent.0.try_wait().unwrap().is_none(),
                "host did not reach {last_step}"
            );
            None
        });
        let exit_deadline = if pause.is_some() {
            observed + Duration::from_millis(1200)
        } else {
            start_deadline
        };
        let status = wait_until(exit_deadline, || parent.0.try_wait().unwrap());
        assert!(status.success(), "fixture parent failed: {status}");
        if pause.is_some() {
            assert!(
                observed.elapsed() >= Duration::from_millis(500),
                "host exited before the injected pause could exercise its deadline"
            );
        }
        assert_eq!(
            fs::read_to_string(checkpoint).unwrap(),
            format!("{last_step}\n")
        );
    }

    fn assert_no_connection(&self) {
        assert_eq!(
            self.listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    fn assert_connection_without_bytes(&self) {
        let (mut socket, _) = self.listener.accept().expect("step 2 must follow connect");
        socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut byte = [0];
        assert_eq!(
            socket.read(&mut byte).unwrap(),
            0,
            "received a byte before authentication"
        );
    }
}

fn wait_until<T>(deadline: Instant, mut check: impl FnMut() -> Option<T>) -> T {
    while Instant::now() < deadline {
        if let Some(result) = check() {
            return result;
        }
        thread::sleep(Duration::from_millis(2));
    }
    panic!("fixture did not reach the expected state before its deadline");
}
