/// Most integration-test targets do not spawn the daemon, but they compile this shared module too.
#[allow(dead_code)]
pub fn ckdev_binary(
    binary: impl AsRef<std::path::Path>,
    scratch_dir: impl AsRef<std::path::Path>,
) -> std::path::PathBuf {
    let binary = binary.as_ref();
    let binary = std::fs::canonicalize(binary)
        .unwrap_or_else(|error| panic!("test binary {} does not exist: {error}", binary.display()));
    let file_name = binary
        .file_name()
        .and_then(|name| name.to_str())
        .expect("test binary has a UTF-8 file name");
    let name = file_name
        .strip_prefix("ckdev-")
        .or_else(|| file_name.strip_prefix("ck-"))
        .unwrap_or(file_name);
    let destination = scratch_dir.as_ref().join(format!("ckdev-{name}"));
    // A hard link preserves the built inode, so macOS does not have to validate
    // a fresh executable copy. Scratch space can be on another volume, where
    // hard links are unavailable, so use a normal copy as the fallback.
    match std::fs::hard_link(&binary, &destination) {
        Ok(()) => {}
        Err(_) => {
            std::fs::copy(&binary, &destination).unwrap_or_else(|error| {
                panic!(
                    "could not create ckdev test binary {} from {}: {error}",
                    destination.display(),
                    binary.display()
                )
            });
        }
    };
    destination
}

pub fn privacy_trampoline() -> std::path::PathBuf {
    let path = std::path::PathBuf::from(env!("CARGO_BIN_EXE_cerebellum-test-privacy-trampoline"));
    assert!(
        path.is_file(),
        "missing test privacy trampoline at {}; run cargo test without --lib to build it",
        path.display()
    );
    path
}
