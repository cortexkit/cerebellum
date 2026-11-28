// Separate test binary: re-executes itself with fenced homes for the embedded daemon.
#![cfg(all(feature = "bridge-test-identities", any(target_os = "linux", windows)))]

#[path = "support/managed_settings.rs"]
mod managed_settings;
mod support;

use serde_json::json;
use std::path::{Path, PathBuf};
use std::{fs, time::Duration};

const RUN_LIMIT: Duration = Duration::from_secs(120);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scratch_subc_serves_the_signed_bridge() {
    // The probe job supplies the rendezvous directory. Feature-enabled unit
    // tests do not start a supervised daemon unless that job is running.
    let Some(coord) = std::env::var_os("CK_BRIDGE_CI_COORD").map(PathBuf::from) else {
        return;
    };
    let Some(home) =
        managed_settings::fenced_home("scratch_subc_serves_the_signed_bridge", RUN_LIMIT).await
    else {
        return;
    };
    let mut module_env = support::fenced_module_env(&home);
    let config =
        cortexkit_test_support::fenced_subc_env_dir(&home, "XDG_CONFIG_HOME").join("cortexkit");
    let data =
        cortexkit_test_support::fenced_subc_env_dir(&home, "XDG_DATA_HOME").join("cortexkit");
    let run = data.join("run");
    fs::create_dir_all(&config).unwrap();
    fs::create_dir_all(&run).unwrap();
    fs::write(config.join("cerebellum.jsonc"), b"{}").unwrap();

    let (override_var, endpoint) = bridge_endpoint(&coord);
    module_env.insert(override_var.into(), PathBuf::from(&endpoint));
    module_env.insert(
        "CK_BRIDGE_TEST_CHECKPOINT".into(),
        coord.join("server-step"),
    );
    let signed_image = PathBuf::from(
        std::env::var_os("CK_BRIDGE_CI_SERVER").expect("signed release daemon image"),
    );
    assert_eq!(signed_image.parent(), Some(coord.as_path()));
    let binary = support::daemon_binary("ckdev-bridge-ci", signed_image);
    let daemon_path = home.join("subc.jsonc");
    fs::write(
        &daemon_path,
        serde_json::to_vec(&json!({
            "version": 1,
            "modules": {
                "cerebellum": {"program": binary, "env": module_env, "reserved": true}
            }
        }))
        .unwrap(),
    )
    .unwrap();

    let daemon_config =
        subc_daemon::bootstrap::BootstrapConfig::new(home.join("subc-connection.json"), 0)
            .with_privacy_trampoline(support::privacy_trampoline())
            .with_daemon_config_path(&daemon_path)
            .unwrap()
            .with_capture_logs_dir(run.join("logs"))
            .with_terminal_journal_path(run.join("terminals.jsonl"))
            .with_live_children_record(run.join("live-children.json"))
            .with_machine_id_path(data.join("machine-id"))
            .with_config_store_root(data.join("config-store"))
            .unwrap();
    let mut daemon = tokio::spawn(subc_daemon::bootstrap::run_with_config(daemon_config));
    let launched = tokio::time::timeout(Duration::from_secs(30), async {
        while !listening(&endpoint) && !daemon.is_finished() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        if daemon.is_finished() {
            panic!(
                "Subc exited before the signed cerebellum listener: {:?}",
                (&mut daemon).await
            );
        }
    })
    .await;
    assert!(
        launched.is_ok(),
        "signed cerebellum did not bind after Subc startup: {}",
        fs::read_to_string(run.join("logs/cerebellum.stderr.log")).unwrap_or_default()
    );
    fs::write(coord.join("endpoint"), &endpoint).unwrap();
    tokio::time::timeout(Duration::from_secs(60), async {
        while !coord.join("stop").exists() {
            assert!(
                !daemon.is_finished(),
                "the scratch Subc daemon quit while the bridge tests were running"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the bridge tests must signal teardown");
    daemon.abort();
    let _ = daemon.await;
}

#[cfg(target_os = "linux")]
fn bridge_endpoint(coord: &Path) -> (&'static str, String) {
    let private = coord.join("bridge");
    cerebellum_core::private_fs::create_dir(&private).unwrap();
    (
        "CK_BRIDGE_TEST_SOCKET",
        private.join("bridge.sock").to_str().unwrap().into(),
    )
}

#[cfg(target_os = "linux")]
fn listening(endpoint: &str) -> bool {
    Path::new(endpoint).exists()
}

#[cfg(windows)]
fn bridge_endpoint(coord: &Path) -> (&'static str, String) {
    (
        "CK_BRIDGE_TEST_PIPE",
        format!(r"\\.\pipe\{}", coord.file_name().unwrap().to_str().unwrap()),
    )
}

#[cfg(windows)]
fn listening(endpoint: &str) -> bool {
    cerebellum_windows::wait_named_pipe(std::ffi::OsStr::new(endpoint), std::num::NonZeroU32::MIN)
        .is_ok()
}
