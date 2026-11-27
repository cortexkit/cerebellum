//! Own binary: spawns real Chrome without competing with the library's parallel tests.

#![cfg(windows)]

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cerebellum_windows::{spawn_with_devtools_pipe, DevToolsProcess};

use cerebellum::browser_launch_readiness::{
    CdpPipeIo, ChildExitStatus, PipeHandshake, PipeHandshakeState, PipeRead,
};
use cerebellum::cdp::WindowsCdpPipe;

// The maximum configured pipe-readiness deadline in browser_config, not the
// 10 s production default. Cold Chrome startup is part of this test.
const HANDSHAKE_CAP_MS: u64 = 30_000;
const EXIT_TIMEOUT_MS: u32 = 30_000;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const KILLED_EXIT_CODE: u32 = 42;

#[test]
fn windows_chrome_devtools_pipe_lifecycle() {
    let chrome = installed_chrome();
    eprintln!("Chrome executable: {}", chrome.display());

    // Start each case with its own never-used profile and a live CDP session.
    let killed_profile = Profile::new("kill");
    let (killed, mut pipe) = start_chrome(&chrome, &killed_profile.0);
    get_version("kill", &killed, &mut pipe);
    killed
        .process
        .terminate(KILLED_EXIT_CODE)
        .expect("kill Chrome");
    assert_eq!(
        killed
            .process
            .wait(EXIT_TIMEOUT_MS)
            .expect("wait for killed Chrome"),
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
    get_version("close", &closed, &mut pipe);
    assert_eq!(
        closed.process.wait(0).expect("check Chrome is running"),
        None
    );
    let (command, mut response) = pipe.into_ends();
    // Chromium invokes CloseBrowserSoon on command-input disconnect. Keep
    // reading possible so closing the response pipe cannot cause this exit.
    // https://github.com/chromium/chromium/blob/main/chrome/browser/devtools/remote_debugging_server.cc#L325-L328
    drop(command);
    assert_eq!(
        closed
            .process
            .wait(EXIT_TIMEOUT_MS)
            .expect("wait for Chrome on EOF"),
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

struct Child {
    process: DevToolsProcess,
    released_at: Instant,
}

impl Drop for Child {
    fn drop(&mut self) {
        if !matches!(self.process.wait(0), Ok(Some(_))) {
            let _ = self.process.terminate(KILLED_EXIT_CODE);
            let _ = self.process.wait(EXIT_TIMEOUT_MS);
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
    let child = Child {
        process,
        released_at: Instant::now(),
    };
    (child, WindowsCdpPipe::new(command, response))
}

fn get_version(case: &str, child: &Child, pipe: &mut WindowsCdpPipe) {
    let mut handshake = PipeHandshake::new(
        child.released_at,
        NonZeroU64::new(HANDSHAKE_CAP_MS).expect("nonzero handshake deadline"),
    )
    .expect("prepare Browser.getVersion");
    // The only pre-handshake write is one small frame into a fresh pipe.
    pipe.write_frame(handshake.request_bytes())
        .expect("send Browser.getVersion");
    let mut buffer = [0; 4096];
    let mut received = 0;
    let mut first_byte_after = None;
    loop {
        let (closed, bytes) = match pipe.read(&mut buffer).expect("read Browser.getVersion") {
            PipeRead::Bytes(count) => (false, &buffer[..count]),
            PipeRead::WouldBlock => (false, &buffer[..0]),
            PipeRead::Closed => (true, &buffer[..0]),
        };
        let exit_code = child.process.wait(0).expect("sample Chrome exit status");
        let observed_at = Instant::now();
        let elapsed = observed_at.duration_since(child.released_at);
        if !bytes.is_empty() {
            received += bytes.len();
            first_byte_after.get_or_insert(elapsed);
        }
        let child_exit = exit_code.map(|code| ChildExitStatus::Code(code as i32));
        match handshake.observe(observed_at, child_exit, closed, bytes) {
            PipeHandshakeState::Pending => thread::sleep(POLL_INTERVAL),
            PipeHandshakeState::Ready(version) => {
                assert!(
                    version.product.starts_with("Chrome/")
                        || version.product.starts_with("HeadlessChrome/"),
                    "{version:?}"
                );
                assert!(!version.protocol_version.is_empty());
                eprintln!(
                    "Browser.getVersion ({case}): {}, protocolVersion={}, elapsed={elapsed:?}, \
                    received={received} B, first_byte_after={first_byte_after:?}, Chrome alive",
                    version.product, version.protocol_version
                );
                return;
            }
            PipeHandshakeState::Failed(error) => {
                let process = match exit_code {
                    Some(code) => format!("Chrome exited: 0x{code:08x} ({code})"),
                    None => "Chrome alive".into(),
                };
                panic!(
                    "Browser.getVersion ({case}) failed: {error:?}; elapsed={elapsed:?}, \
                    received={received} B, first_byte_after={first_byte_after:?}, \
                    response_closed={closed}, {process}"
                );
            }
        }
    }
}

fn expect_response_eof(pipe: &mut WindowsCdpPipe) {
    let deadline = Instant::now() + Duration::from_millis(u64::from(EXIT_TIMEOUT_MS));
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
