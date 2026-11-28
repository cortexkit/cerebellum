#![cfg(all(feature = "bridge-test-identities", any(target_os = "linux", windows)))]

use cerebellum_bridge_protocol::peer_trailer::{parse_public_key, TEST_PEER_PUBLIC_KEY_HEX};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(target_os = "linux")]
#[path = "real_browser_ci/linux.rs"]
mod linux;
#[path = "real_browser_ci/release_sessions.rs"]
mod release_sessions;
#[cfg(windows)]
#[path = "real_browser_ci/windows.rs"]
mod windows;

const READY_LIMIT: Duration = Duration::from_secs(15);
const CHECK_LIMIT: Duration = Duration::from_millis(500);
const SEQUENCE_LIMIT: Duration = Duration::from_secs(2);

// Use another RFC 8032 vector's public key for the parent predicates. This
// selects the native image rules without the signed-test-parent fallback.
const NATIVE_PARENT_KEY: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = if cfg!(windows) {
            std::env::temp_dir()
        } else {
            PathBuf::from("/tmp")
        };
        let path = base.join(format!("ck-browser-{}-{nonce:x}", std::process::id()));
        cerebellum_core::private_fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("could not clean scratch directory {:?}: {error}", self.0);
        }
    }
}

struct Running(Child);

impl Running {
    fn wait(&mut self, context: &str) -> ExitStatus {
        wait_for(context, || self.0.try_wait().unwrap())
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_for<T>(context: &str, mut try_read: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + READY_LIMIT;
    loop {
        if let Some(value) = try_read() {
            return value;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {context}");
        thread::sleep(Duration::from_millis(5));
    }
}

fn sign_copy(source: &Path, destination: &Path, role: &str) {
    let suffix = std::env::consts::EXE_SUFFIX;
    let target = if cfg!(windows) {
        "x86_64-pc-windows-msvc"
    } else {
        "x86_64-unknown-linux-gnu"
    };
    let trailer = std::env::var_os("CK_IMAGE_TEST_TRAILER")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            // The signer is built beside the profile's binaries; this test
            // executable runs from that profile's deps/ directory.
            let exe = std::env::current_exe().unwrap();
            let profile = exe.parent().and_then(Path::parent).unwrap();
            profile.join(format!("peer-trailer{suffix}"))
        });
    fs::copy(source, destination).unwrap();
    let output = Command::new(trailer)
        .args(["sign", "--test-key"])
        .arg(destination)
        .args([role, target, env!("CARGO_PKG_VERSION")])
        .env(
            "CEREBELLUM_BRIDGE_PEER_PUBLIC_KEY",
            TEST_PEER_PUBLIC_KEY_HEX,
        )
        .output()
        .expect("build peer-trailer in the same release profile as the test");
    assert!(
        output.status.success(),
        "fixture signing failed: {output:?}"
    );
}

fn assert_budget(checks: [Duration; 4]) {
    for (name, elapsed) in [
        "step 1 parent",
        "step 2 peer",
        "step 3 peer",
        "step 3 parent",
    ]
    .into_iter()
    .zip(checks)
    {
        println!("{name}: {elapsed:?} (limit {CHECK_LIMIT:?})");
        assert!(elapsed <= CHECK_LIMIT, "{name} took {elapsed:?}");
    }
    let sum: Duration = checks.into_iter().sum();
    println!("four checks: {sum:?} (limit {SEQUENCE_LIMIT:?})");
    assert!(sum <= SEQUENCE_LIMIT, "four checks took {sum:?}");
}
