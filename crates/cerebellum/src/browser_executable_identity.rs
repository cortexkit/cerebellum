//! Platform dispatch for claims about a configured browser executable.

use std::path::Path;

use serde_json::{json, Value};

use crate::browser_launch::ExecutableIdentityClaim;

pub fn verify_configured_executable(
    path: &Path,
    expected: &str,
) -> Result<ExecutableIdentityClaim, Value> {
    #[cfg(target_os = "macos")]
    {
        verify_code_signed_executable(Path::new("/usr/bin/codesign"), path, expected)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (path, expected);
        Err(json!({
            "outcome": "identity_unverifiable",
            "reason": "no_verifier_for_platform",
            "platform": std::env::consts::OS,
        }))
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
    fn platform_without_a_verifier_refuses_as_unverifiable() {
        let refusal = verify_configured_executable(Path::new("/bin/sh"), "configured-identity")
            .expect_err("a platform without a verifier must refuse");

        assert_eq!(refusal["outcome"], "identity_unverifiable");
        assert_eq!(refusal["reason"], "no_verifier_for_platform");
        assert_eq!(refusal["platform"], std::env::consts::OS);
    }
}
