use super::*;
use cerebellum_bridge_protocol::{
    linux, HostParentAttestation, LinuxBrowser, PlatformParentAttestation,
};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;

const CHILD: &str = "linux::fixture_entry";

#[path = "linux_refusals.rs"]
mod refusals;

#[test]
#[ignore = "subprocess entry point"]
fn fixture_entry() {
    let root = PathBuf::from(std::env::var_os("CK_IMAGE_TEST_ROOT").unwrap());
    match std::env::var("CK_IMAGE_TEST_ENTRY").unwrap().as_str() {
        "probe" => run_probe(&root),
        "server" => run_server(&root),
        _ => panic!("unknown fixture entry point"),
    }
}

fn fixture(exe: &Path, root: &Path, entry: &str) -> Command {
    let mut cmd = Command::new(exe);
    cmd.args(["--exact", CHILD, "--ignored", "--nocapture"])
        .env("CK_IMAGE_TEST_ROOT", root)
        .env("CK_IMAGE_TEST_ENTRY", entry)
        .env("HOME", root)
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_CACHE_HOME", root.join("cache"))
        .env("XDG_DATA_HOME", root.join("data"))
        .current_dir(root);
    cmd
}

fn run_probe(root: &Path) {
    let key = parse_public_key(TEST_PEER_PUBLIC_KEY_HEX).unwrap();
    wait_for("the expected parent image", || {
        root.join("begin").exists().then_some(())
    });
    let started = Instant::now();
    let evidence = linux::attest_parent(&parse_public_key(NATIVE_PARENT_KEY).unwrap());
    let step1 = started.elapsed();
    let evidence = match evidence {
        Ok(evidence) => evidence,
        Err(error) => {
            fs::write(root.join("refused"), error.to_string()).unwrap();
            return;
        }
    };
    fs::write(
        root.join("attestation"),
        serde_json::to_vec(evidence.attestation()).unwrap(),
    )
    .unwrap();
    wait_for("permission to connect", || {
        root.join("connect").exists().then_some(())
    });
    evidence.check_before_connect().unwrap();
    let mut stream = UnixStream::connect(root.join("bridge")).unwrap();
    stream.set_read_timeout(Some(READY_LIMIT)).unwrap();
    let step2_start = Instant::now();
    linux::observe_peer(&stream)
        .unwrap()
        .verify_cerebellum(&key)
        .unwrap();
    let step2 = step2_start.elapsed();
    let mut attestation = evidence.attestation().clone();
    if root.join("stale-generation").exists() {
        let HostParentAttestation::Platform(PlatformParentAttestation::Linux {
            start_ticks, ..
        }) = &mut attestation
        else {
            panic!("the real browser must produce a native attestation");
        };
        *start_ticks = start_ticks.checked_add(1).unwrap();
    }
    // The fixture's one-byte barrier orders the timed peer checks without
    // making the server inspect the attestation before verifying the probe.
    stream.write_all(&[1]).unwrap();
    writeln!(stream, "{}", serde_json::to_string(&attestation).unwrap()).unwrap();
    let mut receipt = String::new();
    BufReader::new(stream).read_line(&mut receipt).unwrap();
    let (step3, step3_parent, refusal): (Duration, Duration, Option<String>) =
        serde_json::from_str(&receipt).unwrap();
    if let Some(refusal) = refusal {
        fs::write(root.join("refused"), refusal).unwrap();
    } else {
        assert_budget([step1, step2, step3, step3_parent]);
        fs::write(root.join("accepted"), b"accepted").unwrap();
    }
}

fn run_server(root: &Path) {
    let key = parse_public_key(TEST_PEER_PUBLIC_KEY_HEX).unwrap();
    let listener = UnixListener::bind(root.join("bridge")).unwrap();
    let (mut stream, _) = listener.accept().unwrap();
    stream.set_read_timeout(Some(READY_LIMIT)).unwrap();
    let mut barrier = [0];
    stream.read_exact(&mut barrier).unwrap();
    assert_eq!(barrier, [1]);
    let step3_start = Instant::now();
    let host = linux::observe_peer(&stream)
        .unwrap()
        .verify_host(&key)
        .unwrap();
    let step3 = step3_start.elapsed();
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line).unwrap();
    let attestation = serde_json::from_str(&line).unwrap();
    let parent_start = Instant::now();
    let result = host.recheck_parent(&attestation, &parse_public_key(NATIVE_PARENT_KEY).unwrap());
    let step3_parent = parent_start.elapsed();
    let reply = (
        step3,
        step3_parent,
        result.err().map(|error| error.to_string()),
    );
    writeln!(stream, "{}", serde_json::to_string(&reply).unwrap()).unwrap();
}

struct Browser(Running);

impl Drop for Browser {
    fn drop(&mut self) {
        // The fixture created this process group and owns all its descendants.
        unsafe { libc::kill(-(self.0 .0.id() as libc::pid_t), libc::SIGKILL) };
    }
}

struct Fixture {
    _browser: Browser,
    server: Running,
    scratch: Scratch,
}

impl Fixture {
    fn new(image: &Path, args: &[String]) -> Self {
        Self::start(image, args, false)
    }

    fn start(image: &Path, args: &[String], stop_on_exec: bool) -> Self {
        let scratch = Scratch::new();
        let test = std::env::current_exe().unwrap();
        let probe = scratch.join("probe");
        let server = scratch.join("server");
        sign_copy(&test, &probe, "host");
        sign_copy(&test, &server, "cerebellum");
        let mut server = Running(fixture(&server, &scratch.0, "server").spawn().unwrap());
        wait_for("fixture socket bind", || {
            assert!(
                server.0.try_wait().unwrap().is_none(),
                "server exited before bind"
            );
            scratch.join("bridge").exists().then_some(())
        });
        // Exec changes the executable while preserving the probe's actual
        // parent PID. The supervisor releases the probe only after exec.
        let mut command = Command::new("/usr/bin/python3");
        command
            .args([
                "-c",
                r#"
import os, subprocess, sys
subprocess.Popen([sys.argv[1], '--exact', sys.argv[2], '--ignored', '--nocapture'])
os.execv(sys.argv[3], sys.argv[3:])
"#,
            ])
            .arg(probe)
            .arg(CHILD)
            .arg(image)
            .args(args)
            .env("CK_IMAGE_TEST_ROOT", &scratch.0)
            .env("CK_IMAGE_TEST_ENTRY", "probe")
            .env("HOME", &scratch.0)
            .env("XDG_CONFIG_HOME", scratch.join("config"))
            .env("XDG_CACHE_HOME", scratch.join("cache"))
            .env("XDG_DATA_HOME", scratch.join("data"))
            .current_dir(&scratch.0)
            .process_group(0);
        if stop_on_exec {
            // SAFETY: the closure only uses ptrace and reads errno. It runs
            // in the forked fixture before exec, not in the test process.
            unsafe {
                command.pre_exec(refusals::trace_me);
            }
        }
        let mut browser = Browser(Running(command.spawn().unwrap()));
        let exe = PathBuf::from(format!("/proc/{}/exe", browser.0 .0.id()));
        if stop_on_exec {
            refusals::stop_after_browser_exec(browser.0 .0.id());
            assert_eq!(fs::read_link(&exe).unwrap(), image);
        } else {
            wait_for("the requested browser executable", || {
                assert!(
                    browser.0 .0.try_wait().unwrap().is_none(),
                    "{image:?} exited before the probe"
                );
                fs::read_link(&exe)
                    .is_ok_and(|current| current == image)
                    .then_some(())
            });
        }
        Self {
            _browser: browser,
            server,
            scratch,
        }
    }

    fn step1(&self) -> Result<HostParentAttestation, String> {
        fs::write(self.scratch.join("begin"), []).unwrap();
        wait_for("step 1", || {
            if let Ok(error) = fs::read_to_string(self.scratch.join("refused")) {
                return (!error.is_empty()).then_some(Err(error));
            }
            let bytes = fs::read(self.scratch.join("attestation")).ok()?;
            serde_json::from_slice(&bytes).ok().map(Ok)
        })
    }

    fn finish(&mut self) -> Result<(), String> {
        fs::write(self.scratch.join("connect"), []).unwrap();
        assert!(self.server.wait("step 3").success());
        wait_for("the probe's step 3 receipt", || {
            if let Ok(error) = fs::read_to_string(self.scratch.join("refused")) {
                return (!error.is_empty()).then_some(Err(error));
            }
            fs::read(self.scratch.join("accepted"))
                .is_ok_and(|bytes| bytes == b"accepted")
                .then_some(Ok(()))
        })
    }
}

fn browser_under_test() -> (&'static Path, LinuxBrowser, &'static str) {
    match std::env::var("CK_IMAGE_TEST_DISTRO").as_deref() {
        Ok("ubuntu") => (
            Path::new("/opt/google/chrome/chrome"),
            LinuxBrowser::GoogleChrome,
            "google-chrome-stable",
        ),
        Ok("debian") => (
            Path::new("/usr/lib/chromium/chromium"),
            LinuxBrowser::Chromium,
            "chromium",
        ),
        other => panic!("expected a provisioned Ubuntu or Debian runner, got {other:?}"),
    }
}

fn browser_args(profile: &Path) -> Vec<String> {
    vec![
        "--headless".into(),
        "--no-sandbox".into(),
        "--disable-dev-shm-usage".into(),
        "--no-first-run".into(),
        "--disable-background-networking".into(),
        format!("--user-data-dir={}", profile.display()),
        "about:blank".into(),
    ]
}

#[test]
#[ignore = "requires a real packaged browser; run by the real-browser CI job"]
fn packaged_image_passes_the_four_checks_within_budget() {
    linux::probe_kernel().expect("real-browser CI needs the production kernel floor");
    let (path, expected_browser, name) = browser_under_test();
    let package = Command::new("dpkg-query")
        .args(["--show", "--showformat=${Version}", name])
        .output()
        .unwrap();
    assert!(
        package.status.success(),
        "could not read package version: {package:?}"
    );
    let profile = Scratch::new();
    let mut fixture = Fixture::new(path, &browser_args(&profile.0));
    let HostParentAttestation::Platform(PlatformParentAttestation::Linux {
        browser,
        pid,
        package: attested,
        ..
    }) = fixture.step1().expect("packaged image must pass step 1")
    else {
        panic!("expected native Linux attestation");
    };
    assert_eq!(pid, fixture._browser.0 .0.id());
    assert_eq!(browser, expected_browser);
    assert_eq!(attested.name, name);
    assert_eq!(attested.version.as_bytes(), package.stdout);
    fixture.finish().expect("packaged image must pass step 3");
}

#[test]
#[ignore = "requires packaged Chrome or Chromium; run by the real-browser CI job"]
fn packaged_image_with_stale_parent_generation_is_refused() {
    let profile = Scratch::new();
    let mut fixture = Fixture::new(browser_under_test().0, &browser_args(&profile.0));
    fixture
        .step1()
        .expect("the real image must pass step 1 before changing its claim");
    fs::write(fixture.scratch.join("stale-generation"), []).unwrap();
    let error = fixture.finish().unwrap_err();
    assert_eq!(
        error,
        "Linux parent attestation does not match observed evidence"
    );
}

#[test]
#[ignore = "requires system Python; run by the real-browser CI job"]
fn python_parent_is_refused() {
    let python = fs::canonicalize("/usr/bin/python3").unwrap();
    let fixture = Fixture::new(
        &python,
        &["-c".into(), "import time; time.sleep(30)".into()],
    );
    let error = fixture.step1().unwrap_err();
    assert_eq!(
        error,
        "running browser is outside the allowed package paths"
    );
}
