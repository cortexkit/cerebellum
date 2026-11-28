use super::*;
use cerebellum_bridge_protocol::{Frame, EXTENSION_ORIGIN, PROTOCOL_VERSION};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::process::Stdio;

const PARENT_TEST: &str = "release_sessions::launch_release_host";
const HOST_LIMIT: Duration = Duration::from_millis(2500);
#[cfg(target_os = "linux")]
const ENDPOINT_ENV: &str = "CK_BRIDGE_TEST_SOCKET";
#[cfg(windows)]
const ENDPOINT_ENV: &str = "CK_BRIDGE_TEST_PIPE";

#[test]
#[ignore = "signed test-parent subprocess entry point"]
fn launch_release_host() {
    let root = PathBuf::from(std::env::var_os("CK_BRIDGE_CI_PARENT_ROOT").unwrap());
    #[cfg(target_os = "linux")]
    if root.join("non-dumpable").exists() {
        // SAFETY: changes only this short-lived fixture process.
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) }, 0);
    }
    let started = Instant::now();
    let mut child = Running(
        Command::new(root.join(format!("host{}", std::env::consts::EXE_SUFFIX)))
            .arg(EXTENSION_ORIGIN)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut stdout = child.0.stdout.take().unwrap();
    let mut header = [0; 4];
    let n = stdout.read(&mut header[..1]).unwrap();
    let elapsed = started.elapsed();
    if n == 0 {
        assert_eq!(child.wait("the refused host").code(), Some(1));
        let mut stderr = Vec::new();
        child
            .0
            .stderr
            .take()
            .unwrap()
            .read_to_end(&mut stderr)
            .unwrap();
        assert!(
            stderr.is_empty(),
            "native host leaked stderr during refusal: {stderr:?}"
        );
        fs::write(
            root.join("result"),
            serde_json::to_vec(&(false, elapsed)).unwrap(),
        )
        .unwrap();
        return;
    }
    stdout.read_exact(&mut header[1..]).unwrap();
    let size = u32::from_le_bytes(header) as usize;
    assert!(
        (1..=4096).contains(&size),
        "invalid acceptance frame length: {size}"
    );
    let mut payload = vec![0; size];
    stdout.read_exact(&mut payload).unwrap();
    let elapsed = started.elapsed();
    let reply: Frame = serde_json::from_slice(&payload).unwrap();
    assert!(
        matches!(reply, Frame::HostAccepted { protocol: PROTOCOL_VERSION, epoch } if epoch > 0),
        "{reply:?}"
    );
    drop(child.0.stdin.take());
    assert!(child.wait("the accepted host after stdin EOF").success());
    fs::write(
        root.join("result"),
        serde_json::to_vec(&(true, elapsed)).unwrap(),
    )
    .unwrap();
}

enum Image {
    Signed,
    Unsigned,
    WrongRole,
    BadSignature,
}

struct Session {
    scratch: Scratch,
    parent: PathBuf,
}

impl Session {
    fn new(image: Image, sign_parent: bool) -> Self {
        let scratch = Scratch::new();
        let suffix = std::env::consts::EXE_SUFFIX;
        let host = scratch.join(&format!("host{suffix}"));
        let release = Path::new(env!("CARGO_BIN_EXE_ck-cerebellum-native-host"));
        match image {
            Image::Unsigned => {
                fs::copy(release, &host).unwrap();
            }
            Image::Signed | Image::BadSignature => sign_copy(release, &host, "host"),
            Image::WrongRole => sign_copy(release, &host, "cerebellum"),
        }
        if matches!(image, Image::BadSignature) {
            let mut file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&host)
                .unwrap();
            // The final 12 bytes are the length and magic; the preceding byte
            // is part of the signature. Leave the ELF/PE and trailer framing valid.
            file.seek(SeekFrom::End(-13)).unwrap();
            let mut byte = [0];
            file.read_exact(&mut byte).unwrap();
            file.seek(SeekFrom::End(-13)).unwrap();
            file.write_all(&[byte[0] ^ 1]).unwrap();
        }
        let parent = scratch.join(&format!("parent{suffix}"));
        let test = std::env::current_exe().unwrap();
        if sign_parent {
            sign_copy(&test, &parent, "test-parent");
        } else {
            fs::copy(&test, &parent).unwrap();
        }
        Self { scratch, parent }
    }

    fn start(&self, endpoint: &str) -> Running {
        Running(
            Command::new(&self.parent)
                .args(["--exact", PARENT_TEST, "--ignored", "--nocapture"])
                .envs(cortexkit_test_support::fenced_subc_daemon_env(
                    &self.scratch.0,
                ))
                .env(ENDPOINT_ENV, endpoint)
                .env("CK_BRIDGE_CI_PARENT_ROOT", &self.scratch.0)
                .env("CK_BRIDGE_TEST_CHECKPOINT", self.scratch.join("host-step"))
                .env_remove("CK_BRIDGE_TEST_PAUSE")
                .current_dir(&self.scratch.0)
                .spawn()
                .unwrap(),
        )
    }

    fn outcome(
        &self,
        mut parent: Running,
        label: &str,
        accepted: bool,
        last_host_step: &str,
    ) -> Duration {
        assert!(
            parent.wait(label).success(),
            "test parent failed in {label}"
        );
        let (actual, elapsed): (bool, Duration) =
            serde_json::from_slice(&fs::read(self.scratch.join("result")).unwrap()).unwrap();
        assert_eq!(actual, accepted, "unexpected host result in {label}");
        assert_eq!(
            fs::read_to_string(self.scratch.join("host-step"))
                .unwrap()
                .trim(),
            last_host_step,
            "unexpected host step in {label}"
        );
        println!(
            "{label}: {} after {elapsed:?}",
            if accepted { "accepted" } else { "refused" }
        );
        assert!(elapsed <= HOST_LIMIT, "{label} exceeded {HOST_LIMIT:?}");
        elapsed
    }
}

#[test]
#[ignore = "requires the real-browser job's scratch Subc daemon and signed release build"]
fn signed_release_processes_hold_authentication_boundaries() {
    let root = PathBuf::from(
        std::env::var_os("CK_BRIDGE_CI_COORD").expect("start the scratch Subc daemon first"),
    );
    let endpoint = wait_for("signed release listener", || {
        let endpoint = fs::read_to_string(root.join("endpoint")).ok()?;
        (!endpoint.is_empty()).then_some(endpoint)
    });
    let checkpoint = root.join("server-step");
    let reset = || match fs::remove_file(&checkpoint) {
        Ok(()) => (),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => panic!("could not clear the server checkpoint: {error}"),
    };

    let mut timings = Vec::new();
    for (label, image, parent_signed, accepted, host_step, server_step) in [
        (
            "positive control 1",
            Image::Signed,
            true,
            true,
            "step-2",
            Some("step-3-parent"),
        ),
        (
            "unsigned parent",
            Image::Signed,
            false,
            false,
            "step-1",
            None,
        ),
        (
            "unsigned host",
            Image::Unsigned,
            true,
            false,
            "step-2",
            Some("step-3"),
        ),
        (
            "wrong-role host",
            Image::WrongRole,
            true,
            false,
            "step-2",
            Some("step-3"),
        ),
        (
            "bad-signature host",
            Image::BadSignature,
            true,
            false,
            "step-2",
            Some("step-3"),
        ),
        (
            "positive control 2",
            Image::Signed,
            true,
            true,
            "step-2",
            Some("step-3-parent"),
        ),
        (
            "positive control 3",
            Image::Signed,
            true,
            true,
            "step-2",
            Some("step-3-parent"),
        ),
    ] {
        reset();
        let session = Session::new(image, parent_signed);
        let elapsed = session.outcome(session.start(&endpoint), label, accepted, host_step);
        if let Some(step) = server_step {
            assert_eq!(
                fs::read_to_string(&checkpoint).unwrap().trim(),
                step,
                "{label}"
            );
        } else {
            assert!(
                !checkpoint.exists(),
                "{label} reached verification on the daemon"
            );
        }
        if accepted {
            timings.push(elapsed);
        }
    }
    timings.sort_unstable();
    println!("release host startup to host_accepted (n=3, min/median/max): {timings:?}");
}

#[test]
#[ignore = "requires the real-browser job's gate-open native host"]
fn signed_release_host_sends_no_hello_to_a_squatter() {
    let session = Session::new(Image::Signed, true);
    let endpoint = Squatter::bind(&session.scratch);
    let parent = session.start(endpoint.name());
    endpoint.assert_no_hello();
    session.outcome(
        parent,
        "unsigned server at the override endpoint",
        false,
        "step-2",
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires an unprivileged runner and the signed release build"]
fn signed_release_host_rejects_a_non_dumpable_parent_before_connecting() {
    // A valid trailer on the same fixture normally passes and connects.
    let session = Session::new(Image::Signed, true);
    let endpoint = Squatter::bind(&session.scratch);
    session.outcome(
        session.start(endpoint.name()),
        "dumpable test parent control",
        false,
        "step-2",
    );
    endpoint.assert_no_hello();

    let session = Session::new(Image::Signed, true);
    fs::write(session.scratch.join("non-dumpable"), []).unwrap();
    let endpoint = Squatter::bind(&session.scratch);
    session.outcome(
        session.start(endpoint.name()),
        "non-dumpable signed test parent",
        false,
        "step-1",
    );
    assert_eq!(
        endpoint.1.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[cfg(target_os = "linux")]
struct Squatter(String, std::os::unix::net::UnixListener);

#[cfg(target_os = "linux")]
impl Squatter {
    fn bind(root: &Scratch) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let socket = root.join("squatter");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        listener.set_nonblocking(true).unwrap();
        Self(socket.to_str().unwrap().into(), listener)
    }

    fn name(&self) -> &str {
        &self.0
    }

    fn assert_no_hello(&self) {
        let (mut socket, _) =
            wait_for("host connected to the squatter", || match self.1.accept() {
                Ok(socket) => Some(socket),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => None,
                Err(error) => panic!("squatter accept: {error}"),
            });
        socket.set_read_timeout(Some(HOST_LIMIT)).unwrap();
        assert_eq!(
            socket.read(&mut [0]).unwrap(),
            0,
            "host disclosed hello bytes to the squatter"
        );
    }
}

#[cfg(windows)]
struct Squatter(String, cerebellum_windows::OverlappedPipe);

#[cfg(windows)]
impl Squatter {
    fn bind(root: &Scratch) -> Self {
        let name = format!(
            r"\\.\pipe\{}-squatter",
            root.0.file_name().unwrap().to_str().unwrap()
        );
        let handle = cerebellum_windows::create_test_pipe_instance_default_security(
            std::ffi::OsStr::new(&name),
            4096,
        )
        .unwrap();
        Self(name, cerebellum_windows::OverlappedPipe::new(handle))
    }

    fn name(&self) -> &str {
        &self.0
    }

    fn assert_no_hello(&self) {
        // The caller also requires the step-2 checkpoint, which is written
        // only after a connection succeeds, so a broken pipe alone can't pass.
        let deadline = Instant::now() + HOST_LIMIT;
        loop {
            match self.1.read(&mut [0], Some(deadline)) {
                Ok(read) => {
                    assert_eq!(read, 0, "host disclosed hello bytes to the squatter");
                    return;
                }
                Err(error) if error.raw_os_error() == Some(536) && Instant::now() < deadline => {
                    // ERROR_PIPE_LISTENING: no client yet.
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("squatter pipe: {error}"),
            }
        }
    }
}
