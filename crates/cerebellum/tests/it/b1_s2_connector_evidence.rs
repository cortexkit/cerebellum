use cerebellum::manifest::connector_evidence::{
    connector_evidence_eligibility, ConnectorEvidence, ConnectorTestPlan, EvidenceCaseResult,
    EvidenceSelection, TestPlanCase, REQUIREMENTS,
};
use cerebellum::manifest::{
    capability_relative_eligibility, parse_manifest_pins, CapabilityGateInputs,
    FrozenTypeEvidenceStatus, ManifestPinSet,
};
use serde_json::Value;

fn plan() -> ConnectorTestPlan {
    ConnectorTestPlan {
        schema: "ck-browser-connector-test-plan/v1".into(),
        test_plan_revision: "runner-1".into(),
        cases: vec![TestPlanCase {
            case_id: "custody-and-network".into(),
            requirement_ids: {
                let mut ids: Vec<String> =
                    REQUIREMENTS.iter().map(|id| (*id).to_string()).collect();
                ids.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
                ids
            },
        }],
    }
}

fn evidence(plan: &ConnectorTestPlan) -> ConnectorEvidence {
    ConnectorEvidence {
        schema: "ck-browser-connector-evidence/v1".into(),
        custody_sha256: "a".repeat(64),
        address_policy_sha256: "b".repeat(64),
        runner_revision: "runner-1".into(),
        test_plan_sha256: plan.digest(),
        case_results: plan
            .cases
            .iter()
            .map(|case| EvidenceCaseResult {
                case_id: case.case_id.clone(),
                outcome: "pass".into(),
            })
            .collect(),
    }
}

fn pins() -> ManifestPinSet {
    ManifestPinSet {
        schema: "ck-browser-plane-pins/v1".into(),
        spec_a_contract_sha256: "1".repeat(64),
        spec_b2_contract_bundle_sha256: "2".repeat(64),
        browser_custody_sha256: "a".repeat(64),
        browser_address_policy_sha256: "b".repeat(64),
        browser_connector_evidence_sha256: "c".repeat(64),
        browser_connector_runner_revision: "runner-1".into(),
        browser_connector_test_plan_sha256: "d".repeat(64),
        browser_extraction_corpus_sha256: None,
        browser_extraction_evidence_sha256: None,
        browser_extraction_runner_revision: None,
        browser_type_evidence_eligibility_sha256: None,
    }
}

#[test]
fn checked_in_connector_fixture_artifacts_are_canonical_and_closed() {
    let plan_bytes = include_bytes!("../../resources/b1_s2_connector-test-plan.json");
    let evidence_bytes = include_bytes!("../../resources/b1_s2_connector-evidence.json");
    let plan = ConnectorTestPlan::parse(plan_bytes).unwrap();
    let evidence = ConnectorEvidence::parse(evidence_bytes).unwrap();
    assert_eq!(plan.cases.len(), 1);
    assert_eq!(evidence.case_results.len(), 1);
    assert_eq!(evidence.test_plan_sha256, plan.digest());
}

#[test]
fn connector_evidence_requires_all_closed_requirements_and_exact_case_set() {
    let plan = plan();
    let evidence = evidence(&plan);
    assert_eq!(plan.cases.len(), 1);
    assert_eq!(plan.cases[0].requirement_ids.len(), REQUIREMENTS.len());
    assert_eq!(evidence.case_results.len(), 1);
    assert!(plan.validate().is_ok());
    assert!(evidence.validate().is_ok());
    let selection = EvidenceSelection {
        evidence: &evidence,
        test_plan: &plan,
        selected_evidence_sha256: &evidence.digest(),
        selected_custody_sha256: "a".repeat(64).leak(),
        selected_address_policy_sha256: "b".repeat(64).leak(),
        selected_runner_revision: "runner-1",
        selected_test_plan_sha256: &plan.digest(),
    };
    let eligibility = connector_evidence_eligibility(&selection);
    assert!(
        eligibility.passed(),
        "valid evidence must be eligible: {:?}",
        eligibility.reasons
    );

    let mut incomplete = evidence.clone();
    incomplete.case_results.clear();
    assert!(
        !incomplete.validate().is_err(),
        "shape remains closed before cross-artifact matching"
    );
    let bad = EvidenceSelection {
        evidence: &incomplete,
        ..selection
    };
    let report = connector_evidence_eligibility(&bad);
    assert!(!report.eligible);
    assert!(report.reasons.contains(&"case_set_mismatch"));
}

#[test]
fn connector_evidence_digest_and_runner_mismatches_are_reported() {
    let plan = plan();
    let mut evidence = evidence(&plan);
    evidence.runner_revision = "different-runner".into();
    let selected_evidence = evidence.digest();
    let selected_plan = plan.digest();
    let selection = EvidenceSelection {
        evidence: &evidence,
        test_plan: &plan,
        selected_evidence_sha256: &selected_evidence,
        selected_custody_sha256: &"c".repeat(64),
        selected_address_policy_sha256: &"d".repeat(64),
        selected_runner_revision: "runner-1",
        selected_test_plan_sha256: &selected_plan,
    };
    let report = connector_evidence_eligibility(&selection);
    assert!(!report.eligible);
    assert!(report.reasons.contains(&"custody_digest_mismatch"));
    assert!(report.reasons.contains(&"address_policy_digest_mismatch"));
    assert!(report.reasons.contains(&"runner_revision_mismatch"));
}

/// The digest a caller expects the frozen-type evidence pin to carry.
fn expected_frozen_type_digest() -> String {
    cerebellum::browser_type::computed_eligibility_artifact_digest()
}

/// A pin carrying the expected digest is accepted and retained.
///
/// The other cases here cover the three statuses that OMIT the pin. Without
/// this one the gate could accept nothing at all and they would still pass,
/// since each asserts only that a bad pin was rejected.
#[test]
fn a_frozen_type_evidence_pin_matching_the_expected_digest_is_accepted() {
    let mut value = serde_json::to_value(pins()).unwrap();
    let expected = expected_frozen_type_digest();
    value["browser_type_evidence_eligibility_sha256"] = Value::String(expected.clone());
    let bytes = cerebellum::manifest::custody::canonical_json_bytes(&value);

    let parsed = parse_manifest_pins(&bytes, &expected).unwrap();

    assert_eq!(
        parsed.report.frozen_type_evidence,
        FrozenTypeEvidenceStatus::Accepted
    );
    assert_eq!(
        parsed.pins.browser_type_evidence_eligibility_sha256,
        Some(expected)
    );
}

#[test]
fn checked_in_manifest_pin_fixture_is_canonical_and_common_valid() {
    let bytes = include_bytes!("../../resources/b1_s2_manifest-pins.json");
    let parsed = parse_manifest_pins(bytes, &expected_frozen_type_digest()).unwrap();
    assert_eq!(
        parsed.report.frozen_type_evidence,
        FrozenTypeEvidenceStatus::Absent
    );
    assert!(parsed.pins.validate_common().is_ok());
}

#[test]
fn optional_frozen_type_evidence_is_reported_and_omitted_without_gating_capabilities() {
    let base = pins();
    let expected = "e".repeat(64);
    let mut malformed = serde_json::to_value(&base).unwrap();
    malformed["browser_type_evidence_eligibility_sha256"] = Value::Bool(true);
    let malformed_bytes = cerebellum::manifest::custody::canonical_json_bytes(&malformed);
    let parsed = parse_manifest_pins(&malformed_bytes, &expected).unwrap();
    assert_eq!(
        parsed.report.frozen_type_evidence,
        FrozenTypeEvidenceStatus::OmittedMalformed
    );
    assert!(parsed
        .pins
        .browser_type_evidence_eligibility_sha256
        .is_none());
    let common = CapabilityGateInputs {
        common_artifacts_eligible: true,
        extraction_evidence_eligible: false,
    };
    assert!(capability_relative_eligibility(&parsed.pins, "browser.navigate", common).eligible);
    assert!(capability_relative_eligibility(&parsed.pins, "browser.screenshot", common).eligible);
    assert!(capability_relative_eligibility(&parsed.pins, "browser.click_point", common).eligible);
    assert!(capability_relative_eligibility(&parsed.pins, "browser.wait_for", common).eligible);
    assert!(!capability_relative_eligibility(&parsed.pins, "browser.snapshot", common).eligible);
    assert!(!capability_relative_eligibility(&parsed.pins, "browser.click", common).eligible);

    let mut mismatched = serde_json::to_value(&base).unwrap();
    mismatched["browser_type_evidence_eligibility_sha256"] = Value::String("f".repeat(64));
    let mismatched_bytes = cerebellum::manifest::custody::canonical_json_bytes(&mismatched);
    let parsed = parse_manifest_pins(&mismatched_bytes, &expected).unwrap();
    assert_eq!(
        parsed.report.frozen_type_evidence,
        FrozenTypeEvidenceStatus::OmittedMismatched
    );
    assert!(parsed
        .pins
        .browser_type_evidence_eligibility_sha256
        .is_none());
}

#[test]
fn missing_required_pin_remains_fail_closed_and_extraction_is_capability_relative() {
    let base = pins();
    let mut missing = serde_json::to_value(&base).unwrap();
    missing
        .as_object_mut()
        .unwrap()
        .remove("browser_custody_sha256");
    let bytes = cerebellum::manifest::custody::canonical_json_bytes(&missing);
    assert!(parse_manifest_pins(&bytes, &expected_frozen_type_digest()).is_err());

    let mut extraction = base;
    extraction.browser_extraction_corpus_sha256 = Some("3".repeat(64));
    extraction.browser_extraction_evidence_sha256 = Some("4".repeat(64));
    extraction.browser_extraction_runner_revision = Some("extract-1".into());
    assert!(
        !capability_relative_eligibility(
            &extraction,
            "browser.snapshot",
            CapabilityGateInputs {
                common_artifacts_eligible: true,
                extraction_evidence_eligible: false,
            }
        )
        .eligible
    );
    let common = CapabilityGateInputs {
        common_artifacts_eligible: true,
        extraction_evidence_eligible: false,
    };
    assert!(capability_relative_eligibility(&extraction, "browser.navigate", common).eligible);
    assert!(!capability_relative_eligibility(&extraction, "browser.snapshot", common).eligible);

    extraction.browser_extraction_evidence_sha256 = None;
    assert!(capability_relative_eligibility(&extraction, "browser.navigate", common).eligible);
    assert!(!capability_relative_eligibility(&extraction, "browser.snapshot", common).eligible);
}
