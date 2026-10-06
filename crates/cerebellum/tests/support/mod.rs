pub fn privacy_trampoline() -> std::path::PathBuf {
    let path = std::path::PathBuf::from(env!("CARGO_BIN_EXE_cerebellum-test-privacy-trampoline"));
    assert!(
        path.is_file(),
        "missing test privacy trampoline at {}; run cargo test without --lib to build it",
        path.display()
    );
    path
}
