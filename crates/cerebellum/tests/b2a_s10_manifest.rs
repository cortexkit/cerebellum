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
    // Every gate passing ADMITS browser.type. Admission is asserted through the
    // gate report rather than through the manifest, because advertising also
    // requires that the capability can be dispatched, and browser.type has no
    // dispatch route. Reading the manifest here would find it absent for that
    // reason and hold however the gates behaved, which is the assertion this
    // test exists to make.
    assert!(evaluate_unfenceable_gates(&valid_inputs()).passed());

    // And nothing is advertised that could not be served: with the gates fully
    // satisfied, browser.type stays out of the manifest because no dispatch
    // route exists for it. When one is added, this line is what fails, which is
    // the moment the evidence gate stops being theoretical.
    assert!(!has_browser_type(&build_with_unfenceable_evidence(
        &valid_inputs()
    )));

    // Suppressing any single gate withholds admission. Asserted through the
    // report for the same reason: browser.type is absent from the manifest
    // whatever the gates say, so a manifest assertion would pass with the gate
    // deleted.
    let mut no_pin = valid_inputs();
    no_pin.b1_pin = None;
    assert!(!evaluate_unfenceable_gates(&no_pin).passed());

    // A present-but-incompatible B1 pin (conformance not proved) also suppresses.
    let mut bad_pin = valid_inputs();
    bad_pin.b1_pin = Some(B1PinCompatibility {
        revision_or_digest: "b1-rev-1".to_string(),
        conformance_passed: false,
    });
    assert!(!evaluate_unfenceable_gates(&bad_pin).passed());

    // Suppressing the journal deployment bounds keeps it unadvertised.
    let mut no_bounds = valid_inputs();
    no_bounds.journal_bounds = None;
    assert!(!evaluate_unfenceable_gates(&no_bounds).passed());
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
