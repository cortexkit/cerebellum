#![cfg(all(windows, not(feature = "bridge-test-identities")))]

#[test]
fn normal_windows_host_contains_no_bridge_fixture_hooks() {
    let host = std::fs::read(env!("CARGO_BIN_EXE_ck-cerebellum-native-host")).unwrap();
    for name in [
        "CK_BRIDGE_TEST_PIPE",
        "CK_BRIDGE_TEST_SECOND_USER_SID",
        "CK_BRIDGE_TEST_CHECKPOINT",
        "CK_BRIDGE_TEST_PAUSE",
        "create_test_pipe_instance_default_security",
    ] {
        let utf16: Vec<_> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        for needle in [name.as_bytes(), utf16.as_slice()] {
            assert!(
                !host.windows(needle.len()).any(|bytes| bytes == needle),
                "test-only name in normal host: {name}"
            );
        }
    }
}
