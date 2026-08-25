//! Platform dispatch for claims about a configured browser executable.

use std::ffi::OsString;
use std::path::Path;

use serde_json::{json, Value};

use crate::browser_launch::{ExecutableIdentityClaim, PreSpawnIdentityVerification};

#[cfg(target_os = "linux")]
use crate::browser_launch::{LinuxDryRunObservation, LinuxProcessLauncher};

#[cfg(target_os = "linux")]
pub(crate) fn probe_configured_executable(
    launcher: &mut LinuxProcessLauncher,
    path: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    expected: &str,
) -> Result<LinuxDryRunObservation, Value> {
    launcher
        .probe_configured_executable(path, arguments, environment, expected)
        .map_err(|error| {
            json!({
                "outcome": "identity_unverifiable",
                "reason": format!("{error:?}"),
            })
        })
}

#[cfg(target_os = "linux")]
pub(crate) fn validate_configured_executable_at_load(
    launcher: &mut LinuxProcessLauncher,
    path: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    expected: &str,
) -> Result<(), Value> {
    let expected = expected.to_ascii_lowercase();
    let observation =
        probe_configured_executable(launcher, path, arguments, environment, &expected)?;
    let Some(final_image) = observation.next_exec.as_ref() else {
        if observation.observed.image_sha256 == expected {
            return Ok(());
        }
        return Err(json!({
            "outcome": "executable_identity_mismatch",
            "claim_kind": "image_digest",
            "expected_identity": expected,
            "final_image_path": observation.observed.resolved_path,
            "final_image_sha256": observation.observed.image_sha256,
        }));
    };
    Err(json!({
        "outcome": "executable_identity_mismatch",
        "claim_kind": "image_digest",
        "expected_identity": expected,
        "final_image_path": final_image.resolved_path,
        "final_image_sha256": final_image.image_sha256,
    }))
}

pub fn verify_configured_executable(
    path: &Path,
    expected: &str,
) -> Result<(ExecutableIdentityClaim, PreSpawnIdentityVerification), Value> {
    #[cfg(target_os = "macos")]
    {
        verify_code_signed_executable(Path::new("/usr/bin/codesign"), path, expected)
            .map(|identity| (identity, PreSpawnIdentityVerification::Established))
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(json!({
                "outcome": "identity_unverifiable",
                "reason": "configured_digest_invalid",
                "claim_kind": "image_digest",
            }));
        }
        Ok((
            ExecutableIdentityClaim::ImageDigest {
                sha256: expected.to_ascii_lowercase(),
            },
            PreSpawnIdentityVerification::Unavailable,
        ))
    }
}

#[cfg(target_os = "macos")]
fn verify_code_signed_executable(
    verifier: &Path,
    path: &Path,
    expected: &str,
) -> Result<ExecutableIdentityClaim, Value> {
    let output = std::process::Command::new(verifier)
        .args(["-d", "--verbose=4"])
        .arg(path)
        .output()
        .map_err(|error| {
            identity_unverifiable(if error.kind() == std::io::ErrorKind::NotFound {
                "verifier_missing"
            } else {
                "verifier_failed"
            })
        })?;
    if !output.status.success() {
        return Err(identity_unverifiable("verifier_failed"));
    }

    let details = String::from_utf8_lossy(&output.stderr);
    let mut signing_identifier = None;
    let mut unique_code_hash = None;
    for line in details.lines() {
        if let Some(value) = line.strip_prefix("Identifier=") {
            signing_identifier = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("CDHash=") {
            unique_code_hash = Some(value.to_ascii_lowercase());
        }
    }
    let (Some(signing_identifier), Some(unique_code_hash)) = (signing_identifier, unique_code_hash)
    else {
        return Err(identity_unverifiable("verifier_failed"));
    };
    let observed = ExecutableIdentityClaim::CodeSigned {
        signing_identifier,
        unique_code_hash,
    };
    let configured_matches = observed.matches_configured(expected);
    if !configured_matches {
        return Err(json!({
            "outcome": "executable_identity_mismatch",
            "claim_kind": observed.claim_kind(),
            "expected_identity": expected,
            "observed_identity": observed.display_identity(),
        }));
    }
    Ok(observed)
}

#[cfg(target_os = "macos")]
fn identity_unverifiable(reason: &'static str) -> Value {
    json!({
        "outcome": "identity_unverifiable",
        "reason": reason,
        "claim_kind": "code_signed",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_config_probe_refuses_a_wrapper_pin_with_the_final_image_digest() {
        use std::fs;
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixStream;

        let root = std::env::temp_dir().join(format!(
            "cerebellum-linux-config-probe-{}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create probe fixture directory");
        let wrapper = root.join("wrapper");
        fs::write(&wrapper, "#!/bin/sh\nexec /bin/sleep 30\n").expect("write wrapper fixture");
        let mut permissions = fs::metadata(&wrapper)
            .expect("wrapper metadata")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&wrapper, permissions).expect("make wrapper executable");
        let wrapper_digest = sha256_file_for_test(&wrapper);
        let (command_child, _command_parent) = UnixStream::pair().expect("command pair");
        let (_response_parent, response_child) = UnixStream::pair().expect("response pair");
        let mut launcher =
            LinuxProcessLauncher::new(command_child.as_raw_fd(), response_child.as_raw_fd());

        let refusal = validate_configured_executable_at_load(
            &mut launcher,
            &wrapper,
            &[OsString::from("--remote-debugging-pipe")],
            &[],
            &wrapper_digest,
        )
        .expect_err("a wrapper digest must be refused");

        assert_eq!(refusal["outcome"], "executable_identity_mismatch");
        assert_eq!(
            refusal["final_image_path"],
            fs::canonicalize("/bin/sleep")
                .expect("sleep path")
                .to_string_lossy()
                .as_ref()
        );
        assert_eq!(
            refusal["final_image_sha256"],
            sha256_file_for_test(Path::new("/bin/sleep"))
        );
        fs::remove_dir_all(root).expect("remove probe fixture directory");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_config_probe_accepts_a_pin_for_the_terminal_image_and_reaps_it() {
        use std::fs;
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixStream;

        let root = std::env::temp_dir().join(format!(
            "cerebellum-linux-config-probe-terminal-{}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create terminal probe directory");
        let wrapper = root.join("terminal");
        fs::write(&wrapper, "#!/bin/sh\nexec /bin/sleep 30\n").expect("write terminal wrapper");
        let mut permissions = fs::metadata(&wrapper)
            .expect("terminal metadata")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&wrapper, permissions).expect("make terminal wrapper executable");
        let (command_child, _command_parent) = UnixStream::pair().expect("command pair");
        let (_response_parent, response_child) = UnixStream::pair().expect("response pair");
        let mut launcher =
            LinuxProcessLauncher::new(command_child.as_raw_fd(), response_child.as_raw_fd());
        let expected = sha256_file_for_test(Path::new("/bin/sleep"));

        let observation = probe_configured_executable(
            &mut launcher,
            &wrapper,
            &[OsString::from("--remote-debugging-pipe")],
            &[],
            &expected,
        )
        .expect("terminal image probe");
        assert_eq!(observation.next_exec, None);
        assert_eq!(observation.observed.image_sha256, expected);
        assert_eq!(
            cerebellum_linux::process_start_time(observation.generation.pid),
            cerebellum_linux::ProcessStartTime::NoSuchProcess
        );
        fs::remove_dir_all(root).expect("remove terminal probe directory");
    }

    #[cfg(target_os = "linux")]
    fn sha256_file_for_test(path: &Path) -> String {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(path).expect("read digest fixture");
        format!("{:x}", Sha256::digest(bytes))
    }

    #[cfg(target_os = "macos")]
    fn genuine_mismatch() -> Value {
        verify_code_signed_executable(
            Path::new("/usr/bin/codesign"),
            Path::new("/bin/sh"),
            "identity-that-cannot-match-the-system-shell",
        )
        .expect_err("the system shell must not match the deliberately different identity")
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn verifier_that_cannot_run_is_unverifiable_not_an_identity_mismatch() {
        let refusal = verify_code_signed_executable(
            Path::new("/path/where/codesign/does/not/exist"),
            Path::new("/bin/sh"),
            "com.apple.sh",
        )
        .expect_err("the nonexistent verifier must fail to run");

        assert_eq!(refusal["outcome"], "identity_unverifiable");
        assert_ne!(refusal["outcome"], "executable_identity_mismatch");
        assert_eq!(refusal["reason"], "verifier_missing");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn genuine_identity_mismatch_is_not_reported_as_unverifiable() {
        let refusal = genuine_mismatch();

        assert_eq!(refusal["outcome"], "executable_identity_mismatch");
        assert_ne!(refusal["outcome"], "identity_unverifiable");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn identity_mismatch_refusal_carries_the_claim_kind_as_a_field() {
        let refusal = genuine_mismatch();

        assert_eq!(refusal["claim_kind"], "code_signed");
        assert!(refusal["observed_identity"]
            .as_str()
            .is_some_and(|identity| identity.starts_with("identifier=com.apple.sh;cdhash=")));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn platform_without_a_verifier_uses_configured_digest_for_after_exec_attestation() {
        let (identity, checkpoint) = verify_configured_executable(
            Path::new("/bin/sh"),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("Linux compares the configured digest after exec");

        assert_eq!(
            identity,
            ExecutableIdentityClaim::ImageDigest {
                sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string(),
            }
        );
        assert_eq!(checkpoint, PreSpawnIdentityVerification::Unavailable);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn malformed_configured_digest_remains_unverifiable() {
        let refusal = verify_configured_executable(Path::new("/bin/sh"), &"g".repeat(64))
            .expect_err("an unusable digest must refuse");

        assert_eq!(refusal["outcome"], "identity_unverifiable");
        assert_eq!(refusal["reason"], "configured_digest_invalid");
        assert_eq!(refusal["claim_kind"], "image_digest");
    }
}
