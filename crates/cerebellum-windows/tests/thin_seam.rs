//! Mechanical enforcement of the thin-seam rule.
//!
//! This crate contains the raw Windows calls that would otherwise require
//! `unsafe` in a platform-neutral crate. That boundary remains meaningful only
//! while this crate reports system facts and retains kernel objects without
//! deciding what callers should do with them.
//!
//! These tests read the source rather than link Windows APIs, so they also run
//! on hosts where the library deliberately compiles to nothing. They fail when
//! a workspace dependency, decision-carrying type, or verdict-named function
//! enters the seam.

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
    assert!(
        !found.is_empty(),
        "no source files found, so these checks would pass over nothing"
    );
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

#[test]
fn accessibility_actuator_is_single_pattern_and_has_no_semantic_mapping() {
    let source = std::fs::read_to_string(crate_root().join("src/accessibility.rs"))
        .expect("the accessibility source is readable");
    let invoke_pattern_id = source
        .find("method(element.as_raw(), UIA_InvokePatternId, &mut raw)")
        .expect("the actuator requests the fixed UIA Invoke pattern ID");
    let invoke_slot = source
        .find("const INVOKE_PATTERN_INVOKE: usize = 3;")
        .expect("the actuator calls IUIAutomationInvokePattern::Invoke");
    let entry_point = source
        .find("pub fn invoke_accessibility_element(")
        .expect("the actuator has one fixed-pattern entry point");

    assert!(
        invoke_slot < entry_point && invoke_pattern_id > entry_point,
        "the public entry point must use the fixed Invoke-pattern ABI in its implementation"
    );
    assert!(
        source.contains(".query_interface(&IID_IUI_AUTOMATION_INVOKE_PATTERN)"),
        "the returned IUnknown must become an IUIAutomationInvokePattern before Invoke"
    );
    for unsupported_surface in [
        "SemanticActionIntent",
        "SemanticActionPlatform",
        "UnsupportedSemanticAction",
        "request_accessibility_action",
        "action: &str",
        "action: String",
        "Cancel",
        "ELEMENT_SET_FOCUS",
        "IUIAutomationElement::SetFocus",
    ] {
        assert!(
            !source.contains(unsupported_surface),
            "the Windows seam must not expose `{unsupported_surface}` as another action path"
        );
    }
}

#[test]
fn auto_focus_is_disabled_before_the_reader_can_obtain_an_element() {
    let source = std::fs::read_to_string(crate_root().join("src/accessibility.rs"))
        .expect("the accessibility reader source is readable");
    let disable_focus = source
        .find("Self::put_uia_bool(&automation, UIA2_PUT_AUTO_SET_FOCUS, false)")
        .expect("the reader disables IUIAutomation2 automatic focus");
    let source_ready = source[disable_focus..]
        .find("Ok(Self {")
        .map(|offset| disable_focus + offset)
        .expect("the UIA source is constructed after automatic focus is disabled");
    let first_element = source
        .find("self.element_from_handle(hwnd)")
        .expect("the reader has an element-access call site");

    assert!(
        disable_focus < source_ready && source_ready < first_element,
        "automatic focus must be disabled before any UIA element is obtained"
    );
}
