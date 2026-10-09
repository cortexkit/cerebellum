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

pub fn privacy_trampoline() -> std::path::PathBuf {
    let path = std::path::PathBuf::from(env!("CARGO_BIN_EXE_cerebellum-test-privacy-trampoline"));
    assert!(
        path.is_file(),
        "missing test privacy trampoline at {}; run cargo test without --lib to build it",
        path.display()
    );
    path
}
