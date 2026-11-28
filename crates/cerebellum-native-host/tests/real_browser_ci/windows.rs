use super::*;
use cerebellum_bridge_protocol::{windows, HostParentAttestation, PlatformParentAttestation};
use cerebellum_windows::{
    create_test_pipe_instance_default_security, open_named_pipe_client, system_time_100ns,
    trace_image_checks, ImageCheckTrace, OverlappedPipe,
};
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::os::windows::io::AsHandle;
use std::process::Stdio;

const CHILD: &str = "windows::fixture_entry";

fn env_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name} is not bound")))
}

fn pipe_name(root: &Path) -> OsString {
    format!(r"\\.\pipe\{}", root.file_name().unwrap().to_str().unwrap()).into()
}

fn read_packet(pipe: &OverlappedPipe) -> Vec<u8> {
    let until = Some(Instant::now() + READY_LIMIT);
    let mut packet = Vec::new();
    while packet.len() < 4096 {
        let mut byte = [0];
        assert_eq!(
            pipe.read(&mut byte, until).unwrap(),
            1,
            "pipe closed without a packet"
        );
        if byte == *b"\n" {
            return packet;
        }
        packet.push(byte[0]);
    }
    panic!("fixture packet exceeded its bound");
}

fn write_packet(pipe: &OverlappedPipe, packet: &impl std::fmt::Display) {
    let bytes = format!("{packet}\n");
    let written = pipe
        .write(bytes.as_bytes(), Some(Instant::now() + READY_LIMIT))
        .unwrap();
    assert_eq!(written, bytes.len());
}

#[test]
#[ignore = "subprocess entry point"]
fn fixture_entry() {
    let root = env_path("CK_IMAGE_TEST_ROOT");
    match std::env::var("CK_IMAGE_TEST_ENTRY").unwrap().as_str() {
        "server" => run_server(&root, &pipe_name(&root)),
        "probe" => run_probe(&root, &pipe_name(&root)),
        "cmd-roundtrip" => {
            println!("fixture probe reached stdout");
            eprintln!("fixture probe reached stderr");
        }
        entry => panic!("unknown fixture entry: {entry}"),
    }
}

fn run_probe(root: &Path, name: &OsStr) {
    let key = parse_public_key(TEST_PEER_PUBLIC_KEY_HEX).unwrap();
    println!(
        "step 1 parent starting: Unix epoch ms = {}, probe pid = {}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
        std::process::id(),
    );
    let attest = || windows::attest_parent(&parse_public_key(NATIVE_PARENT_KEY).unwrap());
    let (step1, evidence) = time_parent_check("step 1 parent", attest);
    let evidence = match evidence {
        Ok(evidence) => evidence,
        Err(error) => {
            fs::write(root.join("refused"), error.to_string()).unwrap();
            return;
        }
    };
    evidence.check_before_connect().unwrap();
    let (handle, connected_at) = open_named_pipe_client(name).unwrap();
    let step2_start = Instant::now();
    windows::observe_server_peer(&handle, connected_at)
        .unwrap()
        .verify_cerebellum(&key)
        .unwrap();
    let step2 = step2_start.elapsed();
    let pipe = OverlappedPipe::new(handle);
    let mut attestation = evidence.attestation().clone();
    let HostParentAttestation::Platform(PlatformParentAttestation::Windows {
        chrome,
        launcher,
        ..
    }) = &mut attestation
    else {
        panic!("the real browser chain must produce a native attestation");
    };
    assert_eq!(
        chrome.pid,
        std::env::var("CK_IMAGE_TEST_CHROME_PID")
            .unwrap()
            .parse::<u32>()
            .unwrap()
    );
    assert_ne!(launcher.pid, chrome.pid);
    if root.join("stale-generation").exists() {
        chrome.creation_100ns = chrome.creation_100ns.checked_add(1).unwrap();
    }
    write_packet(&pipe, &1);
    write_packet(&pipe, &serde_json::to_string(&attestation).unwrap());
    let (step3, parent, refusal): (Duration, Duration, Option<String>) =
        serde_json::from_slice(&read_packet(&pipe)).unwrap();
    if let Some(refusal) = refusal {
        fs::write(root.join("refused"), refusal).unwrap();
    } else {
        // Repeat only after all four budgeted checks, in the original probe process.
        let (_, repeat) = time_parent_check("step 1 parent same-process repeat", attest);
        if let Err(error) = repeat {
            println!("step 1 parent same-process repeat refused: {error}");
        }
        assert_budget([step1, step2, step3, parent]);
        fs::write(root.join("accepted"), b"accepted").unwrap();
    }
}

fn time_parent_check<T>(label: &str, check: impl FnOnce() -> T) -> (Duration, T) {
    let ((elapsed, result), trace) = trace_image_checks(|| {
        let started = Instant::now();
        let result = check();
        (started.elapsed(), result)
    });
    println!(
        "{label} timing trace (pid {}): {elapsed:?}",
        std::process::id()
    );
    for item in trace {
        match item {
            ImageCheckTrace::Phase(name, duration) => println!("  {name}: {duration:?}"),
            ImageCheckTrace::TrustStatus {
                status,
                chain_errors,
            } => {
                println!(
                    "  WinVerifyTrust status: {status:#010x}, chain errors: {chain_errors:#010x}"
                );
            }
        }
    }
    (elapsed, result)
}

fn run_server(root: &Path, name: &OsStr) {
    let key = parse_public_key(TEST_PEER_PUBLIC_KEY_HEX).unwrap();
    let handle = create_test_pipe_instance_default_security(name, 4096).unwrap();
    let pipe = OverlappedPipe::new(handle);
    fs::write(root.join("listening"), []).unwrap();
    // The pipe may not have a client yet. Poll only until the probe connects;
    // the first packet is the barrier after its own peer verification.
    let handle = pipe.handle().unwrap();
    wait_for("the fixture pipe client", || {
        cerebellum_windows::named_pipe_client_pid(handle.as_handle()).ok()
    });
    let connected_at = system_time_100ns();
    assert_eq!(read_packet(&pipe), b"1");
    let step3_start = Instant::now();
    let signed_probe = windows::observe_client_peer(handle.as_ref(), connected_at)
        .unwrap()
        .verify_host(&key)
        .unwrap();
    let step3 = step3_start.elapsed();
    let attestation = serde_json::from_slice(&read_packet(&pipe)).unwrap();
    let (parent, refusal) = time_parent_check("step 3 parent separate-process recheck", || {
        signed_probe
            .recheck_parent(&attestation, &parse_public_key(NATIVE_PARENT_KEY).unwrap())
            .err()
            .map(|error| error.to_string())
    });
    write_packet(
        &pipe,
        &serde_json::to_string(&(step3, parent, refusal)).unwrap(),
    );
    // Keep the server handle alive until the probe consumes the receipt.
    wait_for("the probe result", || {
        (root.join("accepted").exists() || root.join("refused").exists()).then_some(())
    });
}

struct Browser(Running);

impl Drop for Browser {
    fn drop(&mut self) {
        if self.0 .0.try_wait().is_ok_and(|status| status.is_none()) {
            let _ = Command::new("taskkill.exe")
                .args(["/T", "/F", "/PID"])
                .arg(self.0 .0.id().to_string())
                .output();
        }
    }
}

fn start_chrome(scratch: &Scratch) -> Browser {
    let image = env_path("CK_IMAGE_TEST_WINDOWS_CHROME");
    let profile = scratch.join("profile");
    let mut browser = Browser(Running(
        Command::new(image)
            .args([
                "--headless",
                "--no-sandbox",
                "--no-first-run",
                "--disable-background-networking",
                "--remote-debugging-port=0",
            ])
            .arg(format!("--user-data-dir={}", profile.display()))
            .arg("about:blank")
            .spawn()
            .unwrap(),
    ));
    wait_for("Chrome's disposable profile", || {
        assert!(
            browser.0 .0.try_wait().unwrap().is_none(),
            "Chrome exited before the predicate fixture"
        );
        profile.join("DevToolsActivePort").exists().then_some(())
    });
    browser
}

struct Suspended {
    child: Running,
    pid: u32,
}

impl Suspended {
    fn image(root: &Scratch, path: &Path) -> Self {
        // Holding the process before main lets the test inspect an actual
        // mapped image that would immediately exit without browser arguments.
        let report = root.join("suspended-pid");
        let stderr = root.join("suspended-stderr");
        let mut child = Running(
            Command::new(env_path("CK_IMAGE_TEST_WINDOWS_LAUNCHER"))
                .arg("suspend")
                .arg(path)
                .arg(&report)
                .stdin(Stdio::piped())
                .stderr(fs::File::create(&stderr).unwrap())
                .spawn()
                .unwrap(),
        );
        let pid = wait_for("the suspended process", || {
            if let Some(status) = child.0.try_wait().unwrap() {
                panic!(
                    "could not start {path:?}: launcher {status}\nstderr: {}",
                    diagnostic(&stderr)
                );
            }
            fs::read_to_string(&report).ok()?.parse().ok()
        });
        Self { child, pid }
    }
}

impl Drop for Suspended {
    fn drop(&mut self) {
        if let Some(mut input) = self.child.0.stdin.take() {
            let _ = writeln!(input);
        }
        assert!(self.child.wait("suspended image cleanup").success());
    }
}

fn diagnostic(path: &Path) -> String {
    match fs::read(path) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(error) => format!("could not read {path:?}: {error}"),
    }
}

fn probe_command(
    scratch: &Scratch,
    parent_pid: u32,
    launcher: Option<&Path>,
    probe: &Path,
    entry: &str,
) -> Command {
    let test_args = format!("--exact {CHILD} --ignored --nocapture");
    let probe_stdout = scratch.join("probe-stdout");
    let probe_stderr = scratch.join("probe-stderr");
    let tail = if launcher.is_some() {
        // cmd strips the outer quotes and redirects the probe itself because
        // parent-fixture.exe launches cmd without passing its stdio handles.
        let mut tail = OsString::from("/D /S /C \"\"");
        tail.push(probe);
        tail.push(format!("\" {test_args} > \""));
        tail.push(&probe_stdout);
        tail.push("\" 2> \"");
        tail.push(&probe_stderr);
        tail.push("\"\"");
        tail
    } else {
        test_args.into()
    };
    let mut command = Command::new(env_path("CK_IMAGE_TEST_WINDOWS_LAUNCHER"));
    command
        .arg(parent_pid.to_string())
        .arg(launcher.unwrap_or(probe))
        // Carry cmd's quotes as data until the fixture calls CreateProcessW.
        .env("CK_IMAGE_TEST_WINDOWS_CHILD_TAIL", tail)
        .env("CK_IMAGE_TEST_ROOT", &scratch.0)
        .env("CK_IMAGE_TEST_ENTRY", entry)
        .env("CK_IMAGE_TEST_CHROME_PID", parent_pid.to_string());
    command
}

fn probe_status(scratch: &Scratch, command: &mut Command) -> ExitStatus {
    let launcher_stderr = scratch.join("launcher-stderr");
    let mut child = Running(
        command
            .stderr(fs::File::create(&launcher_stderr).unwrap())
            .spawn()
            .unwrap(),
    );
    let status = child.wait("the probe command");
    print!(
        "Windows probe launcher status: {status}\n{}",
        diagnostic(&launcher_stderr)
    );
    status
}

fn launch_probe(
    scratch: &Scratch,
    parent_pid: u32,
    launcher: Option<&Path>,
    probe: &Path,
    entry: &str,
    overrides: &[(&str, &Path)],
) {
    let status = probe_status(
        scratch,
        probe_command(scratch, parent_pid, launcher, probe, entry).envs(overrides.iter().copied()),
    );
    assert!(
        status.success(),
        "Windows probe launcher ({status}) failed\nprobe stdout: {}\nprobe stderr: {}",
        diagnostic(&scratch.join("probe-stdout")),
        diagnostic(&scratch.join("probe-stderr"))
    );
}

fn run_case(
    parent_pid: u32,
    launcher: Option<&Path>,
    stale: bool,
    overrides: &[(&str, &Path)],
) -> Result<(), String> {
    let scratch = Scratch::new();
    let signed_probe = scratch.join("probe.exe");
    let signed_server = scratch.join("server.exe");
    let exe = std::env::current_exe().unwrap();
    sign_copy(&exe, &signed_probe, "host");
    sign_copy(&exe, &signed_server, "cerebellum");
    if stale {
        fs::write(scratch.join("stale-generation"), []).unwrap();
    }
    let mut server = Running(
        Command::new(signed_server)
            .args(["--exact", CHILD, "--ignored", "--nocapture"])
            .env("CK_IMAGE_TEST_ROOT", &scratch.0)
            .env("CK_IMAGE_TEST_ENTRY", "server")
            .spawn()
            .unwrap(),
    );
    wait_for("the fixture pipe", || {
        assert!(
            server.0.try_wait().unwrap().is_none(),
            "fixture server failed to bind"
        );
        scratch.join("listening").exists().then_some(())
    });
    launch_probe(
        &scratch,
        parent_pid,
        launcher,
        &signed_probe,
        "probe",
        overrides,
    );
    if launcher.is_some() {
        print!("{}", diagnostic(&scratch.join("probe-stdout")));
    }
    if scratch.join("refused").exists() {
        return Err(fs::read_to_string(scratch.join("refused")).unwrap());
    }
    assert_eq!(fs::read(scratch.join("accepted")).unwrap(), b"accepted");
    assert!(server.wait("the verified fixture server").success());
    Ok(())
}

fn wrong_path(result: Result<(), String>) {
    assert_eq!(
        result.unwrap_err(),
        "Windows image verification refused: UnexpectedPath"
    );
}

#[test]
#[ignore = "requires installed Chrome Stable; run by the real-browser CI job"]
fn cmd_launch_preserves_quoted_probe_path_and_redirection() {
    let scratch = Scratch::new();
    let chrome = start_chrome(&scratch);
    let cmd = env_path("CK_IMAGE_TEST_WINDOWS_CMD");
    let probe = scratch.join("probe with spaces.exe");
    fs::copy(std::env::current_exe().unwrap(), &probe).unwrap();
    launch_probe(
        &scratch,
        chrome.0 .0.id(),
        Some(&cmd),
        &probe,
        "cmd-roundtrip",
        &[],
    );
    let stdout = diagnostic(&scratch.join("probe-stdout"));
    let stderr = diagnostic(&scratch.join("probe-stderr"));
    assert!(stdout.contains("fixture probe reached stdout"), "{stdout}");
    assert!(stderr.contains("fixture probe reached stderr"), "{stderr}");
}

#[test]
#[ignore = "requires installed Chrome Stable; run by the real-browser CI job"]
fn chrome_cmd_and_probe_check_native_identity_and_deadlines() {
    let scratch = Scratch::new();
    let chrome = start_chrome(&scratch);
    let cmd = env_path("CK_IMAGE_TEST_WINDOWS_CMD");
    run_case(chrome.0 .0.id(), Some(&cmd), false, &[]).expect("Chrome / System32 cmd must pass");
    let error = run_case(chrome.0 .0.id(), Some(&cmd), true, &[]).unwrap_err();
    assert_eq!(
        error,
        "Windows parent attestation does not match observed evidence"
    );
    wrong_path(run_case(chrome.0 .0.id(), None, false, &[]));

    let fake_root = scratch.join("system-root");
    let fake_system32 = fake_root.join("System32");
    fs::create_dir_all(&fake_system32).unwrap();
    let fake_cmd = fake_system32.join("cmd.exe");
    fs::copy(&cmd, &fake_cmd).unwrap();
    wrong_path(run_case(chrome.0 .0.id(), Some(&fake_cmd), false, &[]));
    wrong_path(run_case(
        chrome.0 .0.id(),
        Some(&fake_cmd),
        false,
        &[("SystemRoot", &fake_root)],
    ));
}

fn copy_chrome_application(source: &Path, target: &Path) -> std::io::Result<()> {
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let destination = target.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_chrome_application(&entry.path(), &destination)?;
        } else {
            fs::copy(entry.path(), destination)?;
        }
    }
    Ok(())
}

#[test]
#[ignore = "requires Chrome Stable files; run by the real-browser CI job"]
fn signed_chrome_copies_fail_the_machine_path_predicate() {
    let scratch = Scratch::new();
    let native = env_path("CK_IMAGE_TEST_WINDOWS_CHROME");
    let system_cmd = env_path("CK_IMAGE_TEST_WINDOWS_CMD");
    let local_root = Scratch::new();
    let local = local_root.join(r"Google\Chrome\Application\chrome.exe");
    // Windows resolves Chrome's side-by-side assemblies when creating the
    // process, even when the new process stays suspended.
    let source = native.parent().unwrap();
    let target = local.parent().unwrap();
    copy_chrome_application(source, target)
        .unwrap_or_else(|error| panic!("copy Chrome from {source:?} to {target:?}: {error}"));
    let image = Suspended::image(&scratch, &local);
    wrong_path(run_case(
        image.pid,
        Some(&system_cmd),
        false,
        &[("LOCALAPPDATA", &local_root.0)],
    ));
    wrong_path(run_case(
        image.pid,
        Some(&system_cmd),
        false,
        &[("ProgramFiles", &local_root.0)],
    ));
}
