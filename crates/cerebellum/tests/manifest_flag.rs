use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use serde_json::Value;

#[allow(dead_code)]
mod support;

struct TestHome(std::path::PathBuf);

impl TestHome {
    fn new() -> Self {
        // Tests run in parallel threads of one process, and the clock can return
        // the same reading to two of them, so a counter keeps each home distinct.
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "cerebellum-manifest-home-{}-{unique}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn binary() -> &'static Path {
    static BINARY: OnceLock<std::path::PathBuf> = OnceLock::new();
    BINARY.get_or_init(|| {
        let binary = cortexkit_test_support::ckdev_binary(env!("CARGO_BIN_EXE_ck-cerebellum"));
        let binary = support::daemon_binary("ckdev-cerebellum-manifest", binary);
        // Pay macOS's first-execution signature scan before measuring CLI latency.
        assert!(Command::new(&binary)
            .arg("--version")
            .output()
            .unwrap()
            .status
            .success());
        binary
    })
}

fn inspect(home: &Path) -> Value {
    let mut child = Command::new(binary())
        .arg("--manifest")
        .env_clear()
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("XDG_STATE_HOME", home.join("state"))
        .env("XDG_RUNTIME_DIR", home.join("runtime"))
        // If the inspection path reads the launch nonce, its source appears in provenance.
        .env(
            subc_os::LAUNCH_NONCE_ENV,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start --manifest");
    let mut stdout = child.stdout.take().unwrap();
    let out = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let mut stderr = child.stderr.take().unwrap();
    let err = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > Duration::from_secs(3) {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("--manifest exceeded three seconds without a daemon");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = out.join().unwrap();
    let stderr = err.join().unwrap();
    assert!(status.success(), "--manifest failed: {stderr:?}");
    assert!(stderr.is_empty(), "--manifest wrote stderr: {stderr:?}");
    serde_json::from_slice(&stdout).expect("stdout is one JSON manifest, without logs")
}

#[test]
fn manifest_flag_is_isolated_and_reports_build_provenance() {
    let home = TestHome::new();
    let manifest = inspect(home.path());
    let provenance = &manifest["provenance"];
    if let Some(sha) = provenance["build_git_sha"].as_str() {
        assert_eq!(sha.len(), 40);
        assert!(sha
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        assert!(provenance.get("build_git_sha_absence_reason").is_none());
    } else {
        assert!(provenance["build_git_sha_absence_reason"]
            .as_str()
            .is_some_and(|s| !s.is_empty()));
    }
    assert!(provenance.get("launch_nonce_source").is_none());
    assert!(manifest["computer_plane_release"].is_object());
    assert_eq!(
        std::fs::read_dir(home.path()).unwrap().count(),
        0,
        "inspection created home/store directories"
    );
}

#[test]
fn printed_build_provenance_matches_hello() {
    let home = TestHome::new();
    let printed = inspect(home.path());
    let hello = cerebellum::manifest::build("cerebellum");
    let mut provenance = serde_json::to_value(hello.provenance).unwrap();
    // Launch delivery is runtime-only; inspection deliberately never reads the nonce.
    provenance
        .as_object_mut()
        .unwrap()
        .remove("launch_nonce_source");
    assert_eq!(printed["provenance"], provenance);
}

#[test]
fn invalid_configuration_prints_the_no_config_manifest_without_writes() {
    let home = TestHome::new();
    let expected = inspect(home.path());
    let config_dir = home.path().join("config/cortexkit");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config = config_dir.join("cerebellum.jsonc");
    let invalid = "{ invalid configuration";
    std::fs::write(&config, invalid).unwrap();
    assert_eq!(inspect(home.path()), expected);
    assert_eq!(std::fs::read_to_string(&config).unwrap(), invalid);
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 1);
    assert_eq!(std::fs::read_dir(&config_dir).unwrap().count(), 1);
}

#[test]
fn valid_configuration_advertises_browser_tools_without_writes() {
    let home = TestHome::new();
    let config_dir = home.path().join("config/cortexkit");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config = config_dir.join("cerebellum.jsonc");
    let text = r#"{"browser":{"launch_handshake_deadline_ms":10000,"termination_grace_period_ms":5000,"browser_idle_timeout_ms":60000,"browser_exit_observation_deadline_ms":5000,"navigation_settle_deadline_ms":30000}}"#;
    std::fs::write(&config, text).unwrap();
    let manifest = inspect(home.path());
    assert!(manifest["provides"]
        .as_array()
        .unwrap()
        .iter()
        .any(|provider| {
            provider["tools"].as_array().is_some_and(|tools| {
                tools.iter().any(|tool| {
                    tool["name"]
                        .as_str()
                        .is_some_and(|name| name.starts_with("browser"))
                })
            })
        }));
    assert!(manifest.get("browser_surface_refused").is_none());
    assert_eq!(std::fs::read_to_string(&config).unwrap(), text);
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 1);
    assert_eq!(std::fs::read_dir(&config_dir).unwrap().count(), 1);
}
