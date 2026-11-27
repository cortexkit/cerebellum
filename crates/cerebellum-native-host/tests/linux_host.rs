#![cfg(target_os = "linux")]

use cerebellum_bridge_protocol::{EXTENSION_ORIGIN, NATIVE_HOST_NAME};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = PathBuf::from(format!("/tmp/cknh-{}-{nonce}", std::process::id()));
        cerebellum_core::private_fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn host_binary() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_ck-cerebellum-native-host"))
}

#[test]
#[ignore = "requires a build with the Linux bridge gate open"]
fn linux_register_writes_both_manifests_and_preserves_identical_files() {
    use serde_json::{json, Value};

    let expected = json!({
        "name": NATIVE_HOST_NAME,
        "description": "CortexKit Chrome bridge",
        "type": "stdio",
        "path": fs::canonicalize(host_binary()).unwrap(),
        "allowed_origins": [EXTENSION_ORIGIN],
    });
    let modified = UNIX_EPOCH + Duration::from_secs(12_345);
    for (chrome, xdg, expected_base) in [
        (Some("chrome-config"), Some("xdg-config"), "chrome-config"),
        (None, Some("xdg-config"), "xdg-config"),
        (None, None, "home/.config"),
        (Some(""), Some(""), "home/.config"),
    ] {
        let scratch = Scratch::new();
        let root = scratch.path();
        let run = || {
            let mut command = Command::new(host_binary());
            command.arg("--register").env("HOME", root.join("home"));
            for (key, value) in [("CHROME_CONFIG_HOME", chrome), ("XDG_CONFIG_HOME", xdg)] {
                match value {
                    Some("") => command.env(key, ""),
                    Some(dir) => command.env(key, root.join(dir)),
                    None => command.env_remove(key),
                };
            }
            let output = command.output().unwrap();
            assert!(output.status.success(), "{expected_base}: {output:?}");
            assert!(output.stdout.is_empty() && output.stderr.is_empty());
        };
        run();

        let manifests = ["google-chrome", "chromium"].map(|browser| {
            let path = root
                .join(expected_base)
                .join(browser)
                .join(format!("NativeMessagingHosts/{NATIVE_HOST_NAME}.json"));
            let bytes = fs::read(&path).unwrap();
            assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), expected);
            let file = fs::File::options().write(true).open(&path).unwrap();
            file.set_modified(modified).unwrap();
            let inode = file.metadata().unwrap().ino();
            (path, bytes, inode)
        });
        if expected_base != "home/.config" {
            assert!(!root.join("home/.config").exists());
        }
        if expected_base != "xdg-config" {
            assert!(!root.join("xdg-config").exists());
        }

        run();
        for (path, bytes, inode) in manifests {
            assert_eq!(fs::read(&path).unwrap(), bytes);
            let metadata = fs::metadata(path).unwrap();
            assert_eq!(metadata.ino(), inode);
            assert_eq!(metadata.modified().unwrap(), modified);
        }
    }
}

#[cfg(feature = "bridge-test-identities")]
#[path = "linux_host/admission.rs"]
mod admission;
