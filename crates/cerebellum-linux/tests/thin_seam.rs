//! Mechanical enforcement of the thin-seam rule.
//!
//! This crate is the only one permitted to contain `unsafe`, which is what lets
//! `cerebellum-computer` keep `#![forbid(unsafe_code)]` on the crate that will
//! eventually synthesize input events. That bargain holds only while this crate
//! stays a set of raw Linux syscall and procfs readings: it reports what the
//! system says and decides nothing.
//!
//! The rule is also load-bearing for a second reason that is easy to miss.
//! Continuous integration runs on non-Linux hosts, where the Linux-specific
//! implementation is target-gated out and this crate compiles to an empty
//! library. So code added here is code no automated build compiles, let alone
//! tests. Judgment that moves in stops being verified, silently and without a
//! failing check.
//!
//! These tests make the rule mechanical instead of a comment:
//!
//! 1. [`no_dependency_on_any_cerebellum_crate`] fails if this crate takes a
//!    dependency on a plane or the substrate.
//! 2. [`no_policy_type_appears_in_the_seam`] fails if a decision-carrying type
//!    name appears in this crate's source.
//! 3. [`no_function_here_claims_to_judge`] fails if a function is named for a
//!    verdict rather than for a reading.
//!
//! They run on every host, including the ones where the crate itself compiles
//! to nothing, because they read text rather than linking Linux facilities.
//! That is deliberate: the check has to work where the code does not.

use std::path::{Path, PathBuf};

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn source_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, found: &mut Vec<PathBuf>) {
        let entries = std::fs::read_dir(dir).expect("the crate source is readable");
        for entry in entries {
            let path = entry.expect("a readable directory entry").path();
            if path.is_dir() {
                walk(&path, found);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                found.push(path);
            }
        }
    }

    let mut found = Vec::new();
    walk(&crate_root().join("src"), &mut found);
    assert!(!found.is_empty(), "no source files found");
    found
}

const FORBIDDEN_POLICY_TYPES: &[&str] = &[
    "GrantVerification",
    "ProcessGrant",
    "PermissionLiveness",
    "PermissionProbeResult",
    "ContainmentRung",
    "GroundingPolicy",
    "GroundingRequirement",
    "AttendanceLease",
    "AttendanceOutcome",
    "CaptureScope",
    "PixelArtifact",
    "DispatchMode",
    "ComputerCapability",
];

const FORBIDDEN_VERDICT_STEMS: &[&str] = &[
    "authorize",
    "authorise",
    "validate",
    "verify",
    "grant",
    "deny",
    "refuse",
    "admit",
    "trust",
    "sanitize",
    "sanitise",
    "redact",
    "classify",
    "decide",
    "policy",
];

#[test]
fn no_dependency_on_any_cerebellum_crate() {
    let manifest = std::fs::read_to_string(crate_root().join("Cargo.toml"))
        .expect("the crate manifest is readable");

    for (number, line) in manifest.lines().enumerate() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some(name) = line.split(['=', ' ', '.']).next() else {
            continue;
        };
        assert!(
            !name.starts_with("cerebellum"),
            "line {}: this seam must not depend on `{name}`",
            number + 1
        );
    }
}

#[test]
fn no_policy_type_appears_in_the_seam() {
    for path in source_files() {
        let source = std::fs::read_to_string(&path).expect("a readable source file");
        for forbidden in FORBIDDEN_POLICY_TYPES {
            assert!(
                !source.contains(forbidden),
                "{}: `{forbidden}` names a decision rather than a reading",
                path.display()
            );
        }
    }
}

#[test]
fn no_function_here_claims_to_judge() {
    for path in source_files() {
        let source = std::fs::read_to_string(&path).expect("a readable source file");
        for line in source.lines() {
            let trimmed = line.trim_start();
            let Some(rest) = trimmed
                .strip_prefix("pub fn ")
                .or_else(|| trimmed.strip_prefix("pub const fn "))
                .or_else(|| trimmed.strip_prefix("pub unsafe fn "))
            else {
                continue;
            };
            let name = rest.split(['(', '<']).next().unwrap_or_default();
            for stem in FORBIDDEN_VERDICT_STEMS {
                assert!(
                    !name.contains(stem),
                    "{}: `{name}` is named for a verdict rather than a reading",
                    path.display()
                );
            }
        }
    }
}
