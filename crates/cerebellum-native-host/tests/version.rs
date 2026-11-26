use std::process::Command;

#[test]
fn version_prints_name_and_package_version_without_a_browser() {
    let output = Command::new(cortexkit_test_support::ckdev_binary(env!(
        "CARGO_BIN_EXE_ck-cerebellum-native-host"
    )))
    .arg("--version")
    .output()
    .expect("start the native host");

    assert!(output.status.success(), "native host --version failed");
    assert_eq!(
        output.stdout,
        concat!(
            "ck-cerebellum-native-host ",
            env!("CARGO_PKG_VERSION"),
            "\n"
        )
        .as_bytes()
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn a_chrome_invocation_does_not_print_version_text() {
    let output = Command::new(cortexkit_test_support::ckdev_binary(env!(
        "CARGO_BIN_EXE_ck-cerebellum-native-host"
    )))
    .args([
        "chrome-extension://bfmlflnlaflnibiellpjjifdbcifciei/",
        "--version",
    ])
    .output()
    .expect("start the native host without a Chrome parent");

    assert!(!output.status.success(), "a non-Chrome parent was admitted");
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}
