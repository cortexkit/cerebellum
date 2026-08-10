//! Mechanical enforcement of the thin-seam rule.
//!
//! This crate is the only one permitted to contain `unsafe`, which is what lets
//! `cerebellum-computer` keep `#![forbid(unsafe_code)]` on the crate that will
//! eventually synthesize input events. That bargain holds only while this crate
//! stays a set of raw readings: it reports what the system says and decides
//! nothing.
//!
//! The rule is also load-bearing for a second reason that is easy to miss.
//! Continuous integration runs on Linux, where the framework dependencies are
//! target-gated out and this crate compiles to an empty library. So code added
//! here is code no automated build compiles, let alone tests. Judgment that
//! moves in stops being verified, silently and without a failing check.
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
//! to nothing, because they read text rather than linking frameworks. That is
//! deliberate: the check has to work where the code does not.

use std::path::{Path, PathBuf};

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn source_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, found: &mut Vec<PathBuf>) {
        let entries = std::fs::read_dir(dir).expect("the crate's own source directory is readable");
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
    assert!(
        !found.is_empty(),
        "no source files found, so these checks would pass over nothing"
    );
    found
}

/// Type names that carry a decision rather than a reading.
///
/// Each belongs to a judgment this crate must not make: whether a grant still
/// holds, what a permission state implies, how far a containment claim reaches,
/// which grounding path is eligible. A raw reading has no opinion about any of
/// them.
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

/// Function-name stems that promise a verdict.
///
/// A reading is named for what it reports; a verdict is named for what it
/// concludes. The distinction matters here more than elsewhere because a caller
/// reads the name and not the body, and because nothing in this crate is
/// positioned to conclude anything: it cannot see a grant, a policy, or a
/// caller's intent.
///
/// `is_` and `screen_is_locked`-style names are deliberately absent from this
/// list. Reporting that the system says a screen is locked is a reading; the
/// verdict about what that means for a capture belongs to the caller.
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

/// This crate depends on no other crate in the workspace.
///
/// A dependency on a plane or on the substrate is the mechanical signature of
/// judgment moving in: deciding anything about grants, permissions or
/// containment requires those types, so refusing the dependency refuses the
/// decision. It also keeps the dependency arrow pointing one way, which is what
/// lets a plane crate forbid unsafe while using this one.
#[test]
fn no_dependency_on_any_cerebellum_crate() {
    let manifest = std::fs::read_to_string(crate_root().join("Cargo.toml"))
        .expect("the crate's own manifest is readable");

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
            "line {}: this crate must not depend on `{name}`. A workspace dependency here is \
             judgment moving into the seam, and the seam is not compiled by CI.",
            number + 1
        );
    }
}

/// No decision-carrying type appears in this crate's source.
///
/// Checked as text rather than through the type system, because the point is to
/// catch the name arriving at all -- including in a comment that proposes it, or
/// a signature written before the dependency that would make it compile.
#[test]
fn no_policy_type_appears_in_the_seam() {
    for path in source_files() {
        let source = std::fs::read_to_string(&path).expect("a readable source file");
        for forbidden in FORBIDDEN_POLICY_TYPES {
            assert!(
                !source.contains(forbidden),
                "{}: `{forbidden}` names a decision, and this crate reports readings. Whatever \
                 needs it belongs in the platform-neutral code, which every host builds and tests.",
                path.display()
            );
        }
    }
}

/// No function here is named for a verdict.
///
/// The name is the part a caller checks, so a reading wearing a verdict's name
/// invites a caller to treat it as settled. This crate cannot settle anything:
/// it has no access to the grant, the policy, or the request that would decide
/// the question.
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
                    "{}: `{name}` is named for a verdict. Name it for what the system reports, \
                     and leave the conclusion to the code that holds the grant and the policy.",
                    path.display()
                );
            }
        }
    }
}
