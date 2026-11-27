use std::{path::PathBuf, time::Duration};

/// Relaunch with fenced process directories: the embedded daemon resolves its
/// user config path and trust anchor from its own environment.
pub async fn fenced_home(test: &str, hang_guard: Duration) -> Option<PathBuf> {
    const FIXTURE_HOME: &str = "CEREBELLUM_MANAGED_SETTINGS_FIXTURE_HOME";
    if let Some(home) = std::env::var_os(FIXTURE_HOME) {
        return Some(home.into());
    }
    let home = cortexkit_test_support::ScratchDir::new("cerebellum-managed-settings");
    let exe = super::support::daemon_binary(
        "ckdev-cerebellum-settings",
        std::env::current_exe().unwrap(),
    );
    #[allow(
        clippy::disallowed_methods,
        reason = "migrated by the spawn-wrapper slice"
    )]
    let output = tokio::time::timeout(
        hang_guard,
        tokio::process::Command::new(exe)
            .args(["--exact", test, "--nocapture"])
            .envs(cortexkit_test_support::fenced_subc_daemon_env(home.path()))
            .env(FIXTURE_HOME, home.path())
            // Make the daemon keep the key that signs settings views in the
            // fenced home instead of the operator's keychain.
            .env("SUBC_TEST_CONFIG_GATE", "1")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("fenced settings test finished within the hang guard")
    .expect("run the fenced settings test");
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    None
}
