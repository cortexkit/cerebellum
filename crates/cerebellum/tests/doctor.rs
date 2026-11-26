#![cfg(unix)]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use cortexkit_doctor::{runner, FixClass, Mode, Severity};
use cortexkit_doctor_conformance::{Adapter, Outcome};

#[allow(dead_code)]
mod support;

fn program() -> &'static Path {
    static PROGRAM: OnceLock<PathBuf> = OnceLock::new();
    PROGRAM.get_or_init(|| {
        let binary = cortexkit_test_support::ckdev_binary(env!("CARGO_BIN_EXE_ck-cerebellum"));
        support::daemon_binary("ckdev-cerebellum-doctor", binary)
    })
}

fn seed_missing(config: &Path) -> io::Result<()> {
    fs::create_dir_all(config.join("cortexkit"))?;
    let path = serde_json::to_string(&config.join("missing-chrome"))?;
    fs::write(
        config.join("cortexkit/cerebellum.jsonc"),
        format!("// Agent browser settings\n{{\"browser\": {{\"executable_path\": {path},}},}}\n"),
    )
}

struct Homes(PathBuf);

impl Homes {
    fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).unwrap();
        let path = PathBuf::from(format!(
            "/tmp/cerebellum-doctor-homes-{:032x}",
            u128::from_ne_bytes(nonce)
        ));
        cerebellum_core::private_fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Homes {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn doctor_reports_missing_executable_without_starting_module() {
    let home = Homes::new();
    let config = home.0.join("config");
    let data = home.0.join("data");
    seed_missing(&config).unwrap();
    let output = runner::check(
        program(),
        Mode::Quick,
        &runner::Options::new()
            .with_config_home(&config)
            .with_data_home(&data),
    )
    .unwrap();
    let findings = output.findings();
    assert_eq!(findings.len(), 1);
    let found = &findings[0];
    assert_eq!(found.id().as_str(), "browser.executable_missing");
    assert_eq!(found.severity(), Severity::Warning);
    assert_eq!(found.fix().class(), FixClass::None);
    assert!(!data.exists(), "doctor created a module data directory");
}

#[test]
fn doctor_manifest_and_usage_do_not_require_homes() {
    let command = |args: &[&str]| {
        Command::new(program())
            .env_clear()
            .args(args)
            .output()
            .unwrap()
    };
    let manifest = command(&["doctor", "manifest"]);
    assert!(manifest.status.success());
    assert_eq!(manifest.stdout, include_bytes!("../doctor-manifest.json"));
    assert!(manifest.stderr.is_empty());
    let invalid = command(&["doctor", "check", "--manifest"]);
    assert_eq!(invalid.status.code(), Some(2));
    assert!(invalid.stdout.is_empty());
    assert!(invalid.stderr.is_empty());
}

struct Cerebellum;

impl Adapter for Cerebellum {
    fn program(&self) -> &Path {
        program()
    }

    fn seed(&mut self, _data: &Path, config: &Path) -> io::Result<()> {
        seed_missing(config)
    }
}

#[test]
fn production_doctor_passes_read_only_conformance() {
    let rules = cortexkit_doctor_conformance::run(&mut Cerebellum);
    let mut passed = Vec::new();
    let mut skipped = Vec::new();
    for rule in rules {
        match rule.outcome {
            Outcome::Passed => passed.push(rule.name),
            Outcome::Skipped { .. } => skipped.push(rule.name),
            outcome => panic!("{}: {outcome:?}", rule.name),
        }
    }
    passed.sort_unstable();
    skipped.sort_unstable();
    assert_eq!(
        passed,
        [
            "check.full",
            "check.read_only",
            "manifest.digest",
            "manifest.valid",
            "output.valid"
        ]
    );
    // The production binary can prompt, and a scratch image is not a safe
    // re-pin target. Fix callbacks are exercised separately in unit tests.
    assert_eq!(
        skipped,
        [
            "fix.full_recheck",
            "fix.module_running",
            "fix.no_change_on_refusal",
            "fix.no_terminal",
            "fix.stale_digest"
        ]
    );
}
