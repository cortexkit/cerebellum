use super::*;
use crate::user_browser_bridge::socket::read_frame;
use cerebellum_bridge_protocol::{Frame, EXTENSION_ORIGIN, PROTOCOL_VERSION};
use cerebellum_linux::bridge::{read_parent_pid, ProcessStat};
use rustix::net::{
    recvmsg, sendmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};
use serde_json::{json, Value};
use std::io::{IoSlice, IoSliceMut, Read, Seek, SeekFrom, Write};
use std::os::fd::AsFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const FIXTURE: &str = "user_browser_bridge::linux::tests::process::fixture_process";
const LIMIT: Duration = Duration::from_millis(2500);

#[test]
#[ignore = "entry point for signed subprocess fixtures"]
fn fixture_process() {
    let variable = |name| std::env::var_os(name).expect("missing fixture input");
    if variable("CK_FIXTURE_ROLE") == "parent" {
        let status = fixture_command(variable("CK_FIXTURE_CLIENT"))
            .env("CK_FIXTURE_ROLE", "client")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }

    let peer = UnixStream::connect(variable("CK_FIXTURE_BRIDGE")).unwrap();
    let mut observer = UnixStream::connect(variable("CK_FIXTURE_OBSERVER")).unwrap();
    let pid = read_parent_pid();
    let ticks = ProcessStat::read(pid).unwrap().start_ticks;
    let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    let fds = [peer.as_fd()];
    assert!(ancillary.push(SendAncillaryMessage::ScmRights(&fds)));
    assert_eq!(
        sendmsg(
            &observer,
            &[IoSlice::new(b"!")],
            &mut ancillary,
            SendFlags::empty()
        )
        .unwrap(),
        1
    );
    observer.write_all(&pid.to_le_bytes()).unwrap();
    observer.write_all(&ticks.to_le_bytes()).unwrap();
    if variable("CK_FIXTURE_LIFETIME") == "live" {
        // Stay alive without consuming any bytes from the bridge socket.
        let mut byte = [0];
        observer
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        assert_eq!(observer.read(&mut byte).unwrap(), 0);
    }
}

#[tokio::test]
#[ignore = "requires an open CI gate and the peer-trailer binary in the same profile"]
async fn linux_listener_signed_peers_enforce_image_and_hello_order() {
    let fixture = Fixture::new();
    let _listener = fixture.bind();
    for image in [&fixture.unsigned, &fixture.parent, &fixture.invalid] {
        let mut peer = fixture.connect(image, true);
        // An unsigned, wrong-role or invalid-trailer image is refused with no hello at all.
        peer.refused("unsigned_peer").await;
        peer.finish();
    }

    for (reason, field, value) in [
        ("protocol_mismatch", "/protocol", json!(2)),
        (
            "extension_origin_mismatch",
            "/extension_origin",
            json!("chrome-extension://wrong/"),
        ),
        ("parent_attestation_invalid", "/parent/pid", json!(1)),
        (
            "parent_attestation_invalid",
            "/parent/start_ticks",
            json!(0),
        ),
        ("protocol_error", "/parent/v", json!(2)),
    ] {
        let mut peer = fixture.connect(&fixture.host, true);
        let mut hello = peer.hello();
        *hello.pointer_mut(field).unwrap() = value;
        peer.send(hello).await;
        peer.refused(reason).await;
        peer.finish();
    }
    let linux = |browser, manager| {
        json!({"platform":"linux", "v":1, "pid":123, "start_ticks":456,
        "browser":browser, "package":{"manager":manager, "name":"chromium", "version":"1"}})
    };
    for (reason, parent) in [
        ("parent_attestation_invalid", linux("chromium", "dpkg")),
        (
            "parent_attestation_invalid",
            json!({"team_id":"EQHXZ8M8AV", "probe_cdhash":null, "pid":123, "start_time_micros":456}),
        ),
        (
            "parent_attestation_invalid",
            json!({"platform":"windows", "v":1, "chrome":{"pid":123, "creation_100ns":456},
            "launcher":{"pid":124, "creation_100ns":789}}),
        ),
        ("protocol_error", linux("chromium", "rpm")),
        ("protocol_error", linux("another-browser", "dpkg")),
        (
            "protocol_error",
            json!({"platform":"linux-test", "v":1, "pid":123, "start_ticks":456, "extra":true}),
        ),
        (
            "protocol_error",
            json!({"platform":"linux-test", "v":1, "pid":123, "start_ticks":456, "team_id":"EQHXZ8M8AV"}),
        ),
    ] {
        let mut peer = fixture.connect(&fixture.host, true);
        let mut hello = peer.hello();
        hello["parent"] = parent;
        peer.send(hello).await;
        peer.refused(reason).await;
        peer.finish();
    }
}

struct ObservedPeer {
    stream: tokio::net::UnixStream,
    control: UnixStream,
    processes: ChildGuard,
    attestation: Value,
}

impl ObservedPeer {
    fn hello(&self) -> Value {
        json!({"type":"host_hello", "protocol":PROTOCOL_VERSION, "extension_origin":EXTENSION_ORIGIN,
            "parent":self.attestation})
    }

    async fn send(&mut self, hello: Value) {
        let bytes = serde_json::to_vec(&hello).unwrap();
        self.stream
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .await
            .unwrap();
        self.stream.write_all(&bytes).await.unwrap();
    }

    async fn reply(&mut self) -> Frame {
        tokio::time::timeout(LIMIT, read_frame(&mut self.stream))
            .await
            .expect("listener never reached its decision")
            .unwrap()
    }

    async fn refused(&mut self, reason: &str) {
        assert_eq!(
            self.reply().await,
            Frame::HostRefused {
                reason: reason.into()
            }
        );
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(LIMIT, self.stream.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }

    fn finish(self) {
        drop(self.stream);
        drop(self.control);
        assert!(self.processes.finish().success());
    }
}

struct ChildGuard(Child);

impl ChildGuard {
    fn wait(&mut self) -> ExitStatus {
        until(|| self.0.try_wait().unwrap())
    }

    fn finish(mut self) -> ExitStatus {
        self.wait()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.0.try_wait().is_ok_and(|status| status.is_none()) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn until<T>(mut check: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + LIMIT;
    while Instant::now() < deadline {
        if let Some(result) = check() {
            return result;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    panic!("fixture did not reach the expected state before its deadline");
}

fn fixture_command(image: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut command = Command::new(image);
    command
        .args(["--exact", FIXTURE, "--ignored", "--nocapture"])
        .stdout(Stdio::null());
    command
}

fn copy_and_sign(unsigned: &Path, role: &str, filename: &str) -> PathBuf {
    let destination = unsigned.with_file_name(filename);
    fs::copy(unsigned, &destination).unwrap();
    // Build servers may place each executable in a separate artifact directory.
    let signer = std::env::var_os("CK_BRIDGE_FIXTURE_SIGNER")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_exe()
                .unwrap()
                .ancestors()
                .map(|directory| directory.join("peer-trailer"))
                .find(|candidate| candidate.is_file())
                .expect("build peer-trailer in the same profile or set CK_BRIDGE_FIXTURE_SIGNER")
        });
    let target = match (std::env::consts::ARCH, cfg!(target_env = "musl")) {
        ("x86_64", false) => "x86_64-unknown-linux-gnu",
        ("aarch64", false) => "aarch64-unknown-linux-gnu",
        ("x86_64", true) => "x86_64-unknown-linux-musl",
        ("aarch64", true) => "aarch64-unknown-linux-musl",
        _ => panic!("no bridge fixture target triple for this host"),
    };
    let result = Command::new(signer)
        .args(["sign", "--test-key"])
        .arg(&destination)
        .args([role, target, env!("CARGO_PKG_VERSION")])
        .env(
            "CEREBELLUM_BRIDGE_PEER_PUBLIC_KEY",
            TEST_PEER_PUBLIC_KEY_HEX,
        )
        .output()
        .expect("build peer-trailer in the same profile as this test");
    assert!(
        result.status.success(),
        "signing fixture failed: {result:?}"
    );
    destination
}

#[tokio::test]
#[ignore = "requires an open CI gate and the peer-trailer binary in the same profile"]
async fn linux_listener_refuses_exited_peer_while_its_passed_socket_stays_open() {
    let fixture = Fixture::new();
    let _listener = fixture.bind();

    // These tests use a current-thread runtime; the synchronous fixture waits
    // for both subprocesses to exit before letting the listener accept.
    let mut exited = fixture.connect(&fixture.host, false);
    exited.refused("unsigned_peer").await;
    exited.finish();

    let mut live = fixture.connect(&fixture.host, true);
    live.send(live.hello()).await;
    assert!(matches!(
        live.reply().await,
        Frame::HostAccepted {
            protocol: PROTOCOL_VERSION,
            ..
        }
    ));
    live.finish();
}

struct Fixture {
    root: Scratch,
    parent: PathBuf,
    host: PathBuf,
    unsigned: PathBuf,
    invalid: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let key = classify_bridge_gate(REVISION, PUBLIC_KEY).expect("build with the open CI gate");
        assert!(cerebellum_bridge_protocol::peer_trailer::is_test_peer_key(
            &key
        ));
        let root = Scratch::new();
        let unsigned = root.0.join("unsigned");
        fs::copy(std::env::current_exe().unwrap(), &unsigned).unwrap();
        let parent = copy_and_sign(&unsigned, "test-parent", "parent");
        let host = copy_and_sign(&unsigned, "host", "host");
        let invalid = root.0.join("invalid");
        fs::copy(&host, &invalid).unwrap();
        let mut image = fs::File::options()
            .read(true)
            .write(true)
            .open(&invalid)
            .unwrap();
        image.seek(SeekFrom::End(-13)).unwrap(); // last signature byte, before length and magic
        let mut byte = [0];
        image.read_exact(&mut byte).unwrap();
        image.seek(SeekFrom::Current(-1)).unwrap();
        image.write_all(&[byte[0] ^ 1]).unwrap();
        Self {
            root,
            parent,
            host,
            unsigned,
            invalid,
        }
    }

    fn bind(&self) -> SocketListener {
        bind_with(
            UserBrowserBridge::new(),
            REVISION,
            PUBLIC_KEY,
            linux::probe_kernel,
            || Ok((self.root.socket(), SocketPermissions::Private)),
        )
        .unwrap()
    }

    fn connect(&self, image: &Path, live: bool) -> ObservedPeer {
        let control_path = self.root.0.join("observer.sock");
        let listener = UnixListener::bind(&control_path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut processes = ChildGuard(
            fixture_command(&self.parent)
                .env("CK_FIXTURE_ROLE", "parent")
                .env("CK_FIXTURE_CLIENT", image)
                .env("CK_FIXTURE_BRIDGE", self.root.socket())
                .env("CK_FIXTURE_OBSERVER", &control_path)
                .env("CK_FIXTURE_LIFETIME", if live { "live" } else { "exited" })
                .spawn()
                .unwrap(),
        );

        let mut control = until(|| match listener.accept() {
            Ok((stream, _)) => Some(stream),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(
                    processes.0.try_wait().unwrap().is_none(),
                    "fixture exited before passing its fd"
                );
                None
            }
            Err(error) => panic!("fixture control connection failed: {error}"),
        });
        fs::remove_file(control_path).unwrap();
        control.set_read_timeout(Some(LIMIT)).unwrap();
        let mut bytes = [0];
        let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = RecvAncillaryBuffer::new(&mut space);
        let result = recvmsg(
            &control,
            &mut [IoSliceMut::new(&mut bytes)],
            &mut ancillary,
            RecvFlags::CMSG_CLOEXEC,
        )
        .unwrap();
        assert_eq!(result.bytes, 1);
        assert_eq!(&bytes, b"!");
        let mut messages = ancillary.drain();
        let Some(RecvAncillaryMessage::ScmRights(mut fds)) = messages.next() else {
            panic!("fixture did not pass a bridge socket");
        };
        let socket = UnixStream::from(fds.next().unwrap());
        assert!(fds.next().is_none());
        let mut pid = [0; 4];
        let mut ticks = [0; 8];
        control.read_exact(&mut pid).unwrap();
        control.read_exact(&mut ticks).unwrap();
        socket.set_nonblocking(true).unwrap();
        if !live {
            assert!(processes.wait().success());
        }
        ObservedPeer {
            stream: tokio::net::UnixStream::from_std(socket).unwrap(),
            control,
            processes,
            attestation: json!({"platform":"linux-test", "v":1, "pid":u32::from_le_bytes(pid), "start_ticks":u64::from_le_bytes(ticks)}),
        }
    }
}
