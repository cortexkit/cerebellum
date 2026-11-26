#[cfg(target_os = "macos")]
mod macos {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use cerebellum_bridge_protocol::{EXTENSION_ORIGIN, NATIVE_HOST_NAME};
    use serde_json::{json, Value};

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = PathBuf::from(format!(
                "/tmp/cknh-register-{label}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(fs::canonicalize(path).unwrap())
        }

        fn home(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn binary() -> PathBuf {
        cortexkit_test_support::ckdev_binary(env!("CARGO_BIN_EXE_ck-cerebellum-native-host"))
    }

    fn register(home: &Path) -> Output {
        Command::new(binary())
            .arg("--register")
            .env("HOME", home)
            .output()
            .expect("run native-host registration")
    }

    fn manifest_path(home: &Path) -> PathBuf {
        home.join(format!(
            "Library/Application Support/Google/Chrome/NativeMessagingHosts/{NATIVE_HOST_NAME}.json"
        ))
    }

    fn assert_success(output: &Output) {
        assert!(output.status.success(), "registration failed: {output:?}");
        assert!(output.stdout.is_empty(), "registration wrote stdout");
        assert!(output.stderr.is_empty(), "registration wrote stderr");
    }

    fn assert_refusal(output: &Output, reason: &str) {
        assert_eq!(output.status.code(), Some(1), "refusal: {output:?}");
        assert!(output.stdout.is_empty(), "a refusal wrote stdout");
        let stderr = String::from_utf8(output.stderr.clone()).unwrap();
        assert!(
            stderr.ends_with('\n'),
            "refusal lacked its newline: {stderr:?}"
        );
        assert_eq!(stderr.bytes().filter(|byte| *byte == b'\n').count(), 1);
        assert!(
            stderr.contains(reason),
            "refusal did not name {reason}: {stderr:?}"
        );
    }

    #[test]
    fn fresh_registration_writes_the_pinned_manifest_privately() {
        let scratch = Scratch::new("fresh");
        let output = register(scratch.home());
        assert_success(&output);

        let path = manifest_path(scratch.home());
        let bytes = fs::read(&path).unwrap();
        let actual: Value = serde_json::from_slice(&bytes).unwrap();
        let executable = fs::canonicalize(binary()).unwrap();
        assert_eq!(
            actual,
            json!({
                "name": NATIVE_HOST_NAME,
                "description": "CortexKit Chrome bridge",
                "path": executable,
                "type": "stdio",
                "allowed_origins": [EXTENSION_ORIGIN],
            })
        );
        let mut pretty = serde_json::to_vec_pretty(&actual).unwrap();
        pretty.push(b'\n');
        assert_eq!(
            bytes, pretty,
            "manifest was not pretty JSON plus one newline"
        );
        let metadata = fs::symlink_metadata(path).unwrap();
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn identical_registration_is_a_filesystem_no_op() {
        let scratch = Scratch::new("idempotent");
        assert_success(&register(scratch.home()));
        let path = manifest_path(scratch.home());
        let original = fs::read(&path).unwrap();
        let old_time = UNIX_EPOCH + Duration::from_secs(12_345);
        fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(old_time)
            .unwrap();
        let inode = fs::metadata(&path).unwrap().ino();

        assert_success(&register(scratch.home()));

        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(
            metadata.ino(),
            inode,
            "an identical rerun replaced the file"
        );
        assert_eq!(metadata.modified().unwrap(), old_time);
        assert_eq!(fs::read(path).unwrap(), original);
    }

    #[test]
    fn registration_refuses_a_symlink_target() {
        let scratch = Scratch::new("symlink");
        let path = manifest_path(scratch.home());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let outside = scratch.home().join("outside.json");
        fs::write(&outside, b"keep these bytes").unwrap();
        std::os::unix::fs::symlink(&outside, &path).unwrap();

        let output = register(scratch.home());

        assert_refusal(&output, "symlink");
        assert_eq!(fs::read(outside).unwrap(), b"keep these bytes");
        assert!(fs::symlink_metadata(path).unwrap().file_type().is_symlink());
    }

    #[test]
    fn registration_refuses_a_hard_linked_target() {
        let scratch = Scratch::new("hard-link");
        let path = manifest_path(scratch.home());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"keep these bytes").unwrap();
        let other = scratch.home().join("other-name.json");
        fs::hard_link(&path, &other).unwrap();

        let output = register(scratch.home());

        assert_refusal(&output, "more than one link");
        assert_eq!(fs::read(path).unwrap(), b"keep these bytes");
        assert_eq!(fs::read(other).unwrap(), b"keep these bytes");
    }
}

#[cfg(not(target_os = "macos"))]
#[test]
fn registration_on_an_unsupported_platform_prints_usage_and_exits_two() {
    let home =
        std::env::temp_dir().join(format!("cknh-register-unsupported-{}", std::process::id()));
    let output = std::process::Command::new(cortexkit_test_support::ckdev_binary(env!(
        "CARGO_BIN_EXE_ck-cerebellum-native-host"
    )))
    .arg("--register")
    .env("HOME", home)
    .output()
    .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        b"Usage: ck-cerebellum-native-host --register (macOS only)\n"
    );
}
