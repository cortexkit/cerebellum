//! Platform dispatch for claims about a configured browser executable.

#[cfg(target_os = "macos")]
use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::ffi::OsString;
use std::path::Path;

use serde_json::{json, Value};

use crate::browser_launch::{PreSpawnIdentityVerification, VerifiedExecutableIdentity};

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
) -> Result<(VerifiedExecutableIdentity, PreSpawnIdentityVerification), Value> {
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
            VerifiedExecutableIdentity::ImageDigest {
                sha256: expected.to_ascii_lowercase(),
            },
            PreSpawnIdentityVerification::Unavailable,
        ))
    }
}

/// Read every signed slice of the file, then check it against configuration.
///
/// `codesign` invoked without `--arch` reports ONE slice of a universal file,
/// and the slice it picks need not be the one the kernel executes: on macOS 27
/// `/bin/sleep` is `x86_64 arm64e arm64e.x1`, the default read names
/// `arm64e.x1`, and an Apple Silicon machine runs `arm64e`. Storing that one
/// slice as "the identity of this file" made an honest launch look like a
/// substituted binary. Which slice runs is kernel policy, so this reads them
/// all and leaves the choice unpredicted.
#[cfg(target_os = "macos")]
fn verify_code_signed_executable(
    verifier: &Path,
    path: &Path,
    expected: &str,
) -> Result<VerifiedExecutableIdentity, Value> {
    let whole_file = read_signing_details(verifier, path, None)?;
    let Some(architectures) = whole_file
        .format
        .as_deref()
        .and_then(signed_slice_architectures)
    else {
        // Never fall back to the unqualified read: that read is exactly the
        // one that named the wrong slice, so using it here would restore the
        // defect for every file whose format this code cannot enumerate.
        return Err(identity_unverifiable("verifier_failed"));
    };

    let mut signing_identifier: Option<String> = None;
    let mut slice_code_hashes = BTreeSet::new();
    for architecture in &architectures {
        let slice = read_signing_details(verifier, path, Some(architecture))?;
        let (Some(identifier), Some(code_hash)) = (slice.identifier, slice.code_hash) else {
            return Err(identity_unverifiable("verifier_failed"));
        };
        // Asking for an architecture the file does not contain returns some
        // other slice rather than failing, so the answer is checked against
        // the question. Without this, a silently substituted slice would leave
        // the real one out of the set and refuse the launch it should admit.
        if slice.format.as_deref().and_then(signed_slice_architectures)
            != Some(vec![architecture.clone()])
        {
            return Err(identity_unverifiable("verifier_failed"));
        }
        // Slices that disagree about who signed them are not one program, and
        // there would be no single identifier to compare against config.
        match &signing_identifier {
            None => signing_identifier = Some(identifier),
            Some(first) if first != &identifier => {
                return Err(identity_unverifiable("verifier_failed"))
            }
            Some(_) => {}
        }
        slice_code_hashes.insert(code_hash);
    }
    let Some(signing_identifier) = signing_identifier else {
        return Err(identity_unverifiable("verifier_failed"));
    };

    let verified = VerifiedExecutableIdentity::CodeSignedFile {
        signing_identifier,
        slice_code_hashes,
    };
    if !verified.matches_configured(expected) {
        return Err(json!({
            "outcome": "executable_identity_mismatch",
            "claim_kind": verified.claim_kind(),
            "expected_identity": expected,
            "observed_identity": verified.display_identity(),
        }));
    }
    Ok(verified)
}

/// The signing facts one `codesign -d` read reported.
#[cfg(target_os = "macos")]
struct SigningDetails {
    identifier: Option<String>,
    format: Option<String>,
    code_hash: Option<String>,
}

/// Run the verifier once, for the whole file or for one architecture slice.
#[cfg(target_os = "macos")]
fn read_signing_details(
    verifier: &Path,
    path: &Path,
    architecture: Option<&str>,
) -> Result<SigningDetails, Value> {
    let mut command = std::process::Command::new(verifier);
    command.args(["-d", "--verbose=4"]);
    if let Some(architecture) = architecture {
        command.args(["--arch", architecture]);
    }
    let output = command.arg(path).output().map_err(|error| {
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
    let mut parsed = SigningDetails {
        identifier: None,
        format: None,
        code_hash: None,
    };
    for line in details.lines() {
        if let Some(value) = line.strip_prefix("Identifier=") {
            parsed.identifier = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("Format=") {
            parsed.format = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("CDHash=") {
            parsed.code_hash = Some(value.to_ascii_lowercase());
        }
    }
    Ok(parsed)
}

/// The architecture slices a `codesign` `Format=` value names, in file order.
///
/// The shapes seen in the wild all carry the slice list in parentheses:
/// `Mach-O universal (x86_64 arm64e arm64e.x1)`, `Mach-O thin (arm64)`, and
/// `app bundle with Mach-O universal (x86_64 arm64)`. Anything else -- a
/// `generic` signature over something that is not Mach-O, or a shape a later
/// macOS invents -- returns `None`, which callers must treat as "this file's
/// slices are unknown" rather than falling back to a single read.
///
/// Only macOS produces these strings, but parsing them needs no platform, so
/// this is not gated and its behaviour can be tested on any host.
pub fn signed_slice_architectures(format: &str) -> Option<Vec<String>> {
    let opened = format.find('(')?;
    let closed = format.rfind(')')?;
    let listed = format.get(opened + 1..closed)?;
    let architectures: Vec<String> = listed.split_whitespace().map(str::to_string).collect();
    if architectures.is_empty() || !architectures.iter().all(|name| is_architecture_name(name)) {
        return None;
    }
    Some(architectures)
}

/// Whether a token can be an architecture name rather than, say, a flag.
///
/// The names go back to `codesign` as `--arch` arguments, so a token that
/// could be read as an option is refused before it is passed as one.
fn is_architecture_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '_' || character == '.'
        })
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

    #[cfg(target_os = "linux")]
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
            .is_some_and(|identity| identity.starts_with("identifier=com.apple.sh;cdhashes={")));
    }

    #[test]
    fn format_line_parsing() {
        assert_eq!(
            signed_slice_architectures("Mach-O universal (x86_64 arm64e arm64e.x1)"),
            Some(vec![
                "x86_64".to_string(),
                "arm64e".to_string(),
                "arm64e.x1".to_string(),
            ])
        );
        assert_eq!(
            signed_slice_architectures("Mach-O thin (arm64)"),
            Some(vec!["arm64".to_string()])
        );
        assert_eq!(
            signed_slice_architectures("app bundle with Mach-O universal (x86_64 arm64)"),
            Some(vec!["x86_64".to_string(), "arm64".to_string()])
        );
        // A signature over something that is not Mach-O names no slices, and
        // neither does a shape this parser has never seen. Both must refuse
        // rather than resolve to the one slice an unqualified read reports.
        assert_eq!(signed_slice_architectures("generic"), None);
        assert_eq!(signed_slice_architectures("Mach-O universal ()"), None);
        // Slice names are handed back to the verifier as arguments, so a name
        // that could be read as an option is not a name.
        assert_eq!(
            signed_slice_architectures("Mach-O universal (x86_64 --output)"),
            None
        );
    }

    /// Write an executable stand-in for `codesign` that prints the signing
    /// lines the real tool prints, so slice collection can be observed without
    /// depending on which slices this machine's system binaries happen to have.
    #[cfg(target_os = "macos")]
    fn fake_verifier(name: &str, script: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let directory = std::env::temp_dir().join(format!(
            "cerebellum-fake-verifier-{name}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).expect("create fake verifier directory");
        let verifier = directory.join("codesign");
        std::fs::write(&verifier, script).expect("write fake verifier");
        let mut permissions = std::fs::metadata(&verifier)
            .expect("fake verifier metadata")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&verifier, permissions).expect("make fake verifier executable");
        verifier
    }

    #[cfg(target_os = "macos")]
    const TWO_SLICE_VERIFIER: &str = r#"#!/bin/sh
arch=""
while [ $# -gt 0 ]; do
  if [ "$1" = "--arch" ]; then arch="$2"; fi
  shift
done
if [ -z "$arch" ]; then
  echo 'Identifier=com.example.two-slice' >&2
  echo 'Format=Mach-O universal (x86_64 arm64e)' >&2
  echo 'CDHash=1111aaaa' >&2
else
  echo 'Identifier=com.example.two-slice' >&2
  echo "Format=Mach-O thin ($arch)" >&2
  if [ "$arch" = x86_64 ]; then echo 'CDHash=1111AAAA' >&2; else echo 'CDHash=2222bbbb' >&2; fi
fi
"#;

    #[cfg(target_os = "macos")]
    #[test]
    fn every_slice_of_a_universal_file_is_collected_before_spawn() {
        let verifier = fake_verifier("two-slice", TWO_SLICE_VERIFIER);

        let verified = verify_code_signed_executable(
            &verifier,
            Path::new("/bin/sleep"),
            "com.example.two-slice",
        )
        .expect("a two-slice file verifies against its signing identifier");

        // A verifier that read only the unqualified default slice would record
        // one hash here, which is the read that refused honest launches.
        assert_eq!(
            verified,
            VerifiedExecutableIdentity::CodeSignedFile {
                signing_identifier: "com.example.two-slice".to_string(),
                slice_code_hashes: BTreeSet::from(
                    ["1111aaaa".to_string(), "2222bbbb".to_string(),]
                ),
            }
        );
        std::fs::remove_dir_all(verifier.parent().expect("fake verifier directory"))
            .expect("remove fake verifier directory");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn slices_signed_by_different_identifiers_are_unverifiable() {
        let verifier = fake_verifier(
            "split-identifier",
            r#"#!/bin/sh
arch=""
while [ $# -gt 0 ]; do
  if [ "$1" = "--arch" ]; then arch="$2"; fi
  shift
done
if [ -z "$arch" ]; then
  echo 'Identifier=com.example.first' >&2
  echo 'Format=Mach-O universal (x86_64 arm64e)' >&2
else
  echo "Format=Mach-O thin ($arch)" >&2
  if [ "$arch" = x86_64 ]; then
    echo 'Identifier=com.example.first' >&2
  else
    echo 'Identifier=com.example.second' >&2
  fi
  echo 'CDHash=3333cccc' >&2
fi
"#,
        );

        let refusal =
            verify_code_signed_executable(&verifier, Path::new("/bin/sleep"), "com.example.first")
                .expect_err("slices that name different signers are not one program");

        assert_eq!(refusal["outcome"], "identity_unverifiable");
        assert_eq!(refusal["reason"], "verifier_failed");
        std::fs::remove_dir_all(verifier.parent().expect("fake verifier directory"))
            .expect("remove fake verifier directory");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn an_unparseable_format_refuses_instead_of_reading_one_slice() {
        let verifier = fake_verifier(
            "generic-format",
            "#!/bin/sh\necho 'Identifier=com.example.generic' >&2\necho 'Format=generic' >&2\necho 'CDHash=4444dddd' >&2\n",
        );

        let refusal = verify_code_signed_executable(
            &verifier,
            Path::new("/bin/sleep"),
            "com.example.generic",
        )
        .expect_err("a format naming no slices cannot be enumerated");

        assert_eq!(refusal["outcome"], "identity_unverifiable");
        assert_eq!(refusal["reason"], "verifier_failed");
        std::fs::remove_dir_all(verifier.parent().expect("fake verifier directory"))
            .expect("remove fake verifier directory");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_real_system_binary_verifies_through_the_real_verifier() {
        let (verified, checkpoint) =
            verify_configured_executable(Path::new("/bin/sleep"), "com.apple.sleep")
                .expect("verify the system sleep binary");

        assert_eq!(checkpoint, PreSpawnIdentityVerification::Established);
        let VerifiedExecutableIdentity::CodeSignedFile {
            signing_identifier,
            slice_code_hashes,
        } = &verified
        else {
            panic!("a macOS executable verifies as a code-signed file");
        };
        assert_eq!(signing_identifier, "com.apple.sleep");
        // How many slices Apple ships varies by release, so the claim here is
        // only that the real tool was driven end to end. That the set contains
        // the slice the kernel actually runs is proved by the launch test that
        // spawns this binary and re-reads the running image.
        assert!(!slice_code_hashes.is_empty());
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
            VerifiedExecutableIdentity::ImageDigest {
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
