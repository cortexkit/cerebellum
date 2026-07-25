//! S10 acceptance tests: unfenceable-capability manifest advertisement.
//!
//! Drives the public manifest constructor and proves the negative acceptance:
//! advertisement stays suppressed when any gate fails, the legacy
//! eligibility-digest-only path is superseded, and a missing external release
//! input is reported distinctly from an implementation failure.

use cerebellum::journal::JournalConfig;
use cerebellum::manifest::{
    build_with_unfenceable_evidence, evaluate_unfenceable_gates, B1PinCompatibility,
    UnfenceableReleaseInputs,
};
use cerebellum::EvidenceEligibilityInput;
use subc_protocol::manifest::{ModuleManifest, ProviderRole};

const BROWSER_TYPE_TOOL: &str = "browser.type";

fn valid_evidence() -> EvidenceEligibilityInput {
    let digest = cerebellum::browser_type::computed_eligibility_artifact_digest();
    EvidenceEligibilityInput {
        manifest_digest: Some(digest.clone()),
        source_lock_digest: Some(digest.clone()),
        computed_artifact_digest: Some(digest),
        ..EvidenceEligibilityInput::default()
    }
}

fn valid_inputs() -> UnfenceableReleaseInputs {
    UnfenceableReleaseInputs {
        evidence: Some(valid_evidence()),
        b1_pin: Some(B1PinCompatibility {
            revision_or_digest: "b1-rev-1".to_string(),
            conformance_passed: true,
        }),
        journal_bounds: Some(JournalConfig {
            journal_retention_bytes: 1_000_000,
            journal_max_entry_bytes: 100_000,
        }),
        computed_max_entry_bytes: Some(100_000),
    }
}

fn has_browser_type(manifest: &ModuleManifest) -> bool {
    let ProviderRole::ToolProvider { tools, .. } = &manifest.provides[0] else {
        panic!("expected a ToolProvider role");
    };
    tools.iter().any(|tool| tool.name == BROWSER_TYPE_TOOL)
}

#[test]
fn advertisement_suppressed_when_a_gate_fails() {
    // Every gate passing advertises browser.type.
    assert!(has_browser_type(&build_with_unfenceable_evidence(
        &valid_inputs()
    )));

    // Suppressing the immutable B1 pin (absent) keeps it unadvertised.
    let mut no_pin = valid_inputs();
    no_pin.b1_pin = None;
    assert!(!has_browser_type(&build_with_unfenceable_evidence(&no_pin)));

    // A present-but-incompatible B1 pin (conformance not proved) also suppresses.
    let mut bad_pin = valid_inputs();
    bad_pin.b1_pin = Some(B1PinCompatibility {
        revision_or_digest: "b1-rev-1".to_string(),
        conformance_passed: false,
    });
    assert!(!has_browser_type(&build_with_unfenceable_evidence(
        &bad_pin
    )));

    // Suppressing the journal deployment bounds keeps it unadvertised.
    let mut no_bounds = valid_inputs();
    no_bounds.journal_bounds = None;
    assert!(!has_browser_type(&build_with_unfenceable_evidence(
        &no_bounds
    )));
}

#[test]
fn legacy_digest_only_path_is_superseded() {
    // A valid browser evidence artifact alone (the legacy path) does NOT
    // advertise browser.type once the B1 pin and B2A gates are required.
    let digest_only = UnfenceableReleaseInputs {
        evidence: Some(valid_evidence()),
        ..UnfenceableReleaseInputs::default()
    };
    assert!(!has_browser_type(&build_with_unfenceable_evidence(
        &digest_only
    )));
}

#[test]
fn missing_input_and_implementation_failure_are_distinct() {
    let bounds = JournalConfig {
        journal_retention_bytes: 1_000_000,
        journal_max_entry_bytes: 100_000,
    };

    // Missing external input: the B1 pin is absent.
    let missing = UnfenceableReleaseInputs {
        evidence: Some(valid_evidence()),
        b1_pin: None,
        journal_bounds: Some(bounds),
        computed_max_entry_bytes: Some(100_000),
    };
    let missing_report = evaluate_unfenceable_gates(&missing);
    assert_eq!(missing_report.missing_inputs(), vec!["b1_journal_pin"]);
    assert!(missing_report.implementation_failures().is_empty());
    assert!(!missing_report.passed());

    // Implementation failure: the B1 pin is present but conformance failed.
    let failed = UnfenceableReleaseInputs {
        evidence: Some(valid_evidence()),
        b1_pin: Some(B1PinCompatibility {
            revision_or_digest: "b1-rev-1".to_string(),
            conformance_passed: false,
        }),
        journal_bounds: Some(bounds),
        computed_max_entry_bytes: Some(100_000),
    };
    let failed_report = evaluate_unfenceable_gates(&failed);
    assert_eq!(
        failed_report.implementation_failures(),
        vec!["b1_journal_pin"]
    );
    assert!(failed_report.missing_inputs().is_empty());
    assert!(!failed_report.passed());

    // The two facts never collapse into one outcome.
    assert_ne!(missing_report.outcomes, failed_report.outcomes);
}
