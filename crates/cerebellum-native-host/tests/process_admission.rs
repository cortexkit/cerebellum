use std::process::Command;

#[cfg(target_os = "macos")]
#[test]
fn non_chrome_parent_exits_silently_without_connecting_or_reading_fabricated_frames() {
    use std::io::Write;
    use std::os::unix::net::UnixListener;
    use std::process::Stdio;

    // A short private scratch path fits macOS's Unix-socket pathname limit.
    let root = std::path::PathBuf::from(format!("/tmp/cknh-parent-{}", std::process::id()));
    cerebellum_core::private_fs::create_dir(&root).unwrap();
    struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _scratch = Scratch(root.clone());
    let endpoint = root.join("cortexkit/run/cerebellum/user-browser.sock");
    cerebellum_core::private_fs::create_dir_all(endpoint.parent().unwrap()).unwrap();
    let listener = UnixListener::bind(endpoint).unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut child = Command::new(cortexkit_test_support::ckdev_binary(env!(
        "CARGO_BIN_EXE_ck-cerebellum-native-host"
    )))
    .arg("chrome-extension://abcdefghijklmnopabcdefghijklmnop/")
    .env("XDG_DATA_HOME", &root)
    .env("HOME", &root)
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    let fabricated = br#"{"type":"page_content","text":"must not leave this process"}"#;
    if let Some(mut stdin) = child.stdin.take() {
        // The host may exit before this write; BrokenPipe is also a refusal.
        let _ = stdin.write_all(&(fabricated.len() as u32).to_ne_bytes());
        let _ = stdin.write_all(fabricated);
    }
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn unsupported_platform_exits_without_stdio_output() {
    let output = Command::new(cortexkit_test_support::ckdev_binary(env!(
        "CARGO_BIN_EXE_ck-cerebellum-native-host"
    )))
    .arg("chrome-extension://abcdefghijklmnopabcdefghijklmnop/")
    .output()
    .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}
