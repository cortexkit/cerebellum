/// The in-process daemon takes module environments as JSON, not OS strings.
/// Keep the shared fence's paths intact when encoding that configuration.
pub fn fenced_module_env(
    scratch: &std::path::Path,
) -> std::collections::BTreeMap<String, std::path::PathBuf> {
    cortexkit_test_support::fenced_subc_daemon_env(scratch)
        .into_iter()
        .map(|(name, path)| {
            (
                name.into_string().expect("fenced variable name is UTF-8"),
                std::path::PathBuf::from(path),
            )
        })
        .collect()
}

#[cfg(unix)]
#[path = "../../src/content_named_fixture.rs"]
mod content_named_fixture;

/// Copy a test executable under `/tmp` before handing it to the daemon.
///
/// The daemon starts modules through a privacy trampoline, making each module
/// responsible for its own privacy prompts. A binary in Cargo's build tree may
/// live on a removable volume, so launching it there can prompt the operator
/// for access on every build. The fixture copy stays on the internal disk and
/// keeps its original executable mode.
#[cfg(unix)]
pub fn daemon_binary(label: &str, path: impl AsRef<std::path::Path>) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let path = path.as_ref();
    let metadata = std::fs::metadata(path).expect("stat the test executable");
    let bytes = std::fs::read(path).expect("read the test executable");
    content_named_fixture::content_named_fixture(
        label,
        label,
        &bytes,
        metadata.permissions().mode() & 0o777,
    )
}

#[cfg(not(unix))]
pub fn daemon_binary(label: &str, path: impl AsRef<std::path::Path>) -> std::path::PathBuf {
    let _ = label;
    path.as_ref().to_path_buf()
}

pub fn privacy_trampoline() -> std::path::PathBuf {
    let path = std::path::PathBuf::from(env!("CARGO_BIN_EXE_cerebellum-test-privacy-trampoline"));
    assert!(
        path.is_file(),
        "missing test privacy trampoline at {}; run cargo test without --lib to build it",
        path.display()
    );
    daemon_binary("test-privacy-trampoline", path)
}

#[allow(dead_code)]
pub fn nonce_holder() -> std::path::PathBuf {
    let path = std::path::PathBuf::from(env!("CARGO_BIN_EXE_cerebellum-test-nonce-holder"));
    assert!(
        path.is_file(),
        "missing test nonce holder at {}",
        path.display()
    );
    daemon_binary("test-nonce-holder", path)
}

/// Runs the module named in `NONCE_LAUNCH_PROGRAM` without the daemon's
/// registration channel; see `tests/support/nonce_launcher.rs`.
#[allow(dead_code)]
pub fn nonce_launcher() -> std::path::PathBuf {
    let path = std::path::PathBuf::from(env!("CARGO_BIN_EXE_cerebellum-test-nonce-launcher"));
    assert!(
        path.is_file(),
        "missing test nonce launcher at {}",
        path.display()
    );
    daemon_binary("test-nonce-launcher", path)
}
