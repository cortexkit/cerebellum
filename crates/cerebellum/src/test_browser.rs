//! Unit-test browser launches run headlessly, without a visible window or Dock icon.

use std::ffi::OsString;

fn assert_headless(arguments: &[OsString]) {
    assert!(
        arguments.iter().any(|arg| arg == "--headless=new"),
        "test browser requires --headless=new"
    );
    assert!(
        arguments.iter().any(|arg| arg == "--remote-debugging-pipe"),
        "test browser requires --remote-debugging-pipe"
    );
    assert!(
        !arguments.iter().any(|arg| {
            let arg = arg.to_string_lossy();
            arg.starts_with("--headless") && arg != "--headless=new"
        }),
        "test browser must not override --headless=new"
    );
}

#[cfg(target_os = "macos")]
pub(crate) fn spawn_for_test(
    executable: &std::path::Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    command_fd: std::os::fd::RawFd,
    response_fd: std::os::fd::RawFd,
) -> Result<cerebellum_macos::BarredChild, cerebellum_macos::SpawnError> {
    if matches!(executable.to_str(), Some("/bin/sleep" | "/bin/sh")) {
        // Fixed command-line fixtures exercise image attestation, not a browser.
        return cerebellum_macos::spawn_barred(
            executable,
            arguments,
            environment,
            command_fd,
            response_fd,
        );
    }
    spawn_barred(executable, arguments, environment, command_fd, response_fd)
}

#[cfg(target_os = "macos")]
pub(crate) fn spawn_barred(
    executable: &std::path::Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    command_fd: std::os::fd::RawFd,
    response_fd: std::os::fd::RawFd,
) -> Result<cerebellum_macos::BarredChild, cerebellum_macos::SpawnError> {
    assert_headless(arguments);
    record(executable, arguments, None);
    let child = cerebellum_macos::spawn_barred(
        executable,
        arguments,
        environment,
        command_fd,
        response_fd,
    )?;
    record(executable, arguments, Some(child.generation().pid));
    Ok(child)
}

#[cfg(target_os = "macos")]
fn record(executable: &std::path::Path, arguments: &[OsString], pid: Option<u32>) {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    use std::sync::{Mutex, OnceLock};

    static AUDIT: OnceLock<Mutex<std::fs::File>> = OnceLock::new();
    let mut audit = AUDIT
        .get_or_init(|| {
            let directory = "/tmp/cereb-headless-spawns";
            if let Err(error) = std::fs::DirBuilder::new().mode(0o700).create(directory) {
                assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
            }
            let metadata =
                std::fs::symlink_metadata(directory).expect("test browser audit directory");
            assert!(
                metadata.file_type().is_dir(),
                "test browser audit must be a directory, not a link"
            );
            assert_eq!(
                metadata.permissions().mode() & 0o077,
                0,
                "test browser audit directory must be private"
            );
            let path = format!("{directory}/{}.jsonl", std::process::id());
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .expect("create private test browser spawn audit");
            eprintln!("test browser spawn audit: {path}");
            Mutex::new(file)
        })
        .lock()
        .expect("test browser spawn audit lock");
    // Only launch metadata is recorded, never data read from a browser profile.
    let entry = serde_json::json!({
        "event": if pid.is_some() { "spawned" } else { "attempt" },
        "test": std::thread::current().name(),
        "executable": executable,
        "arguments": arguments.iter().map(|arg| arg.to_string_lossy()).collect::<Vec<_>>(),
        "pid": pid,
    });
    writeln!(audit, "{entry}").expect("write test browser spawn audit");
    audit.flush().expect("flush test browser spawn audit");
}

#[test]
fn accepts_only_new_headless_with_a_pipe() {
    assert_headless(&["--headless=new".into(), "--remote-debugging-pipe".into()]);
}

#[test]
#[should_panic(expected = "test browser requires --headless=new")]
fn headed_browser_is_refused_before_spawn() {
    assert_headless(&["--remote-debugging-pipe".into()]);
}

#[cfg(target_os = "macos")]
#[test]
#[should_panic(expected = "test browser requires --headless=new")]
fn a_headed_launch_panics_before_the_platform_spawn() {
    let _ = spawn_barred(
        std::path::Path::new("/nonexistent/cerebellum-test-browser-guard"),
        &["--remote-debugging-pipe".into()],
        &[],
        -1,
        -1,
    );
}

#[test]
#[should_panic(expected = "test browser requires --remote-debugging-pipe")]
fn a_debugging_port_is_not_a_pipe() {
    assert_headless(&["--headless=new".into(), "--remote-debugging-port=0".into()]);
}

#[test]
#[should_panic(expected = "test browser must not override --headless=new")]
fn a_headless_override_is_refused() {
    assert_headless(&[
        "--headless=new".into(),
        "--remote-debugging-pipe".into(),
        "--headless=false".into(),
    ]);
}
