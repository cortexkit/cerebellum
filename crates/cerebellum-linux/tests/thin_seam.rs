//! Mechanical enforcement of the thin-seam rule.
//!
//! This crate reports Linux readings and owns the syscalls that require unsafe.
//! It decides nothing about whether those readings satisfy a browser policy.

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
