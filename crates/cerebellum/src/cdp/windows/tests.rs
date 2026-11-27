use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cerebellum_windows::{spawn_with_devtools_pipe, DevToolsProcess};

use super::{CdpPipeIo, PipeRead, WindowsCdpPipe};
use crate::browser_launch_readiness::{BrowserVersion, PipeHandshake, PipeHandshakeState};

const TIMEOUT_MS: u32 = 30_000;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const KILLED_EXIT_CODE: u32 = 42;

#[test]
fn windows_chrome_devtools_pipe_lifecycle() {
    let chrome = installed_chrome();
    eprintln!("Chrome executable: {}", chrome.display());

    // Start each case with its own never-used profile and a live CDP session.
    let killed_profile = Profile::new("kill");
    let (killed, mut pipe) = start_chrome(&chrome, &killed_profile.0);
    report_version("kill", get_version(&mut pipe));
    killed.0.terminate(KILLED_EXIT_CODE).expect("kill Chrome");
    assert_eq!(
        killed.0.wait(TIMEOUT_MS).expect("wait for killed Chrome"),
        Some(KILLED_EXIT_CODE)
    );
    expect_response_eof(&mut pipe);
    let error = pipe
        .write_frame(b"{}\0")
        .expect_err("writer must detect that Chrome's reader is gone");
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe, "{error}");
    eprintln!("Forced exit: response EOF, command write failed with {error}");
    drop(pipe);

    let closed_profile = Profile::new("close");
    let (closed, mut pipe) = start_chrome(&chrome, &closed_profile.0);
    report_version("close", get_version(&mut pipe));
    assert_eq!(closed.0.wait(0).expect("check Chrome is running"), None);
    let WindowsCdpPipe {
        command,
        mut response,
    } = pipe;
    // Chromium invokes CloseBrowserSoon on command-input disconnect. Keep
    // reading possible so closing the response pipe cannot cause this exit.
    // https://github.com/chromium/chromium/blob/main/chrome/browser/devtools/remote_debugging_server.cc#L325-L328
    drop(command);
    assert_eq!(
        closed.0.wait(TIMEOUT_MS).expect("wait for Chrome on EOF"),
        Some(0),
        "Chrome should exit cleanly when only its command writer is closed"
    );
    let mut byte = [0];
    assert_eq!(response.try_read(&mut byte).expect("response EOF"), 0);
    eprintln!(
        "Parent command writer closed: Chrome exited with code 0 and its response reached EOF"
    );
}

fn installed_chrome() -> PathBuf {
    if let Some(path) = env::var_os("CHROME_PATH") {
        let path = std::path::absolute(PathBuf::from(path)).expect("resolve CHROME_PATH");
        assert!(
            path.is_file(),
            "CHROME_PATH is not a file: {}",
            path.display()
        );
        return path;
    }
    let paths = [
        ("ProgramFiles", r"C:\Program Files"),
        ("ProgramFiles(x86)", r"C:\Program Files (x86)"),
    ]
    .map(|(key, fallback)| {
        PathBuf::from(env::var_os(key).unwrap_or_else(|| OsString::from(fallback)))
            .join(r"Google\Chrome\Application\chrome.exe")
    });
    paths
        .iter()
        .find(|path| path.is_file())
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "Google Chrome not found at {} or {}; set CHROME_PATH to chrome.exe",
                paths[0].display(),
                paths[1].display()
            )
        })
}

struct Profile(PathBuf);

impl Profile {
    fn new(case: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("current timestamp")
            .as_nanos();
        // Spaces exercise Windows argument quoting without a machine-specific
        // expectation about where the temp directory is located.
        let path = env::temp_dir().join(format!(
            "cerebellum Chrome pipe {} {nonce} {case}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create a fresh Chrome profile");
        Self(path)
    }
}

impl Drop for Profile {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!(
                "Could not remove disposable profile {}: {error}",
                self.0.display()
            );
        }
    }
}

struct Child(DevToolsProcess);

impl Drop for Child {
    fn drop(&mut self) {
        if !matches!(self.0.wait(0), Ok(Some(_))) {
            let _ = self.0.terminate(KILLED_EXIT_CODE);
            let _ = self.0.wait(TIMEOUT_MS);
        }
    }
}

fn start_chrome(chrome: &Path, profile: &Path) -> (Child, WindowsCdpPipe) {
    let mut profile_arg = OsString::from("--user-data-dir=");
    profile_arg.push(profile);
    let arguments = [
        OsString::from("--headless=new"),
        OsString::from("--no-first-run"),
        OsString::from("--no-default-browser-check"),
        OsString::from("--disable-background-networking"),
        profile_arg,
        OsString::from("about:blank"),
    ];
    let (process, command, response) =
        spawn_with_devtools_pipe(chrome, &arguments).expect("spawn disposable headless Chrome");
    (Child(process), WindowsCdpPipe::new(command, response))
}

fn get_version(pipe: &mut WindowsCdpPipe) -> BrowserVersion {
    let mut handshake = PipeHandshake::new(
        Instant::now(),
        NonZeroU64::new(u64::from(TIMEOUT_MS)).expect("nonzero timeout"),
    )
    .expect("prepare Browser.getVersion");
    // The only pre-handshake write is one small frame into a fresh pipe.
    pipe.write_frame(handshake.request_bytes())
        .expect("send Browser.getVersion");
    let mut buffer = [0; 4096];
    loop {
        let (closed, bytes) = match pipe.read(&mut buffer).expect("read Browser.getVersion") {
            PipeRead::Bytes(count) => (false, &buffer[..count]),
            PipeRead::WouldBlock => (false, &buffer[..0]),
            PipeRead::Closed => (true, &buffer[..0]),
        };
        match handshake.observe(Instant::now(), None, closed, bytes) {
            PipeHandshakeState::Pending => thread::sleep(POLL_INTERVAL),
            PipeHandshakeState::Ready(version) => return version,
            PipeHandshakeState::Failed(error) => panic!("Chrome handshake failed: {error:?}"),
        }
    }
}

fn report_version(case: &str, version: BrowserVersion) {
    assert!(
        version.product.starts_with("Chrome/") || version.product.starts_with("HeadlessChrome/"),
        "{version:?}"
    );
    assert!(!version.protocol_version.is_empty());
    eprintln!(
        "Browser.getVersion ({case}): {}, protocolVersion={}",
        version.product, version.protocol_version
    );
}

fn expect_response_eof(pipe: &mut WindowsCdpPipe) {
    let deadline = Instant::now() + Duration::from_millis(u64::from(TIMEOUT_MS));
    let mut buffer = [0; 4096];
    loop {
        match pipe.read(&mut buffer).expect("read after Chrome exit") {
            PipeRead::Closed => return,
            PipeRead::WouldBlock => thread::sleep(POLL_INTERVAL),
            PipeRead::Bytes(_) => {}
        }
        assert!(
            Instant::now() < deadline,
            "Chrome response never reached EOF"
        );
    }
}
