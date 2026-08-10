//! Capability manifest for ck-cerebellum.
//!
//! Spec A advertises exactly one application capability, `browser.status`, with
//! `execution_mode: pure`. Standard wire-v2 health, discovery, and control
//! surfaces (route.bind, route.status, health.check) are NOT application
//! capabilities — they are advertised in the HELLO `control_ops` grant, not in
//! the manifest's `provides` list.

use serde_json::{json, Value};

pub mod connector_evidence {
    pub use crate::connector_evidence::*;
}
pub mod custody {
    pub use crate::custody::*;
}

pub use connector_evidence::{
    admission_proof_is_current, connector_evidence_eligibility, verify_connector_evidence,
    ConnectorEvidence, ConnectorTestPlan, EvidenceCaseResult, EvidenceEligibility,
    EvidenceSelection, TestPlanCase, REQUIREMENTS as CONNECTOR_REQUIREMENTS,
};
pub use custody::{
    arguments_are_quarantinable, canonical_json_bytes, sha256_file, sha256_hex,
    verify_registration, verify_registration_in_profile_directory, verify_registration_path,
    ConnectorAdmissionProof, CustodyArtifact, CustodyArtifactError, LaunchError, LaunchQuarantine,
    LaunchStage, QuarantineMechanism, RegistrationError, RegistrationObservation, SpawnObservation,
};

use crate::browser_type::{
    browser_type_registration_eligible, EvidenceEligibilityInput,
    BROWSER_EVIDENCE_ELIGIBILITY_SHA256, BROWSER_TYPE_TOOL,
};
use crate::journal::JournalConfig;
use subc_protocol::manifest::{
    Bindings, Concurrency, ExecutionMode, IdentityBinding, IdentityScope, ManagementOperation,
    ManagementOperationKind, ModuleManifest, ProviderRole, StorageBinding, StorageKind,
    StorageScope, Tool, TrustTier,
};
use subc_protocol::PROTOCOL_VERSION;

/// The single application capability this module advertises.
pub const BROWSER_STATUS: &str = "browser.status";

/// Build the browser-free cerebellum capability manifest.
///
/// The default manifest declares exactly one `ToolProvider` role with the
/// browser.status tool (`execution_mode: pure`). Minted browser routes are added
/// only by `build_with_browser_plane_pins` after their independent release gates
/// pass; this builder never adds the legacy type route.
/// The management operations this module serves.
///
/// Built from the same names the dispatcher matches on, so an operation cannot
/// be advertised without being routable: the list and the routing read one
/// constant rather than two that agree until someone edits one.
///
/// Separate from the tool surface because the two differ in kind, not only in
/// envelope. A tool call acts; a management operation arranges the authority
/// under which acting is possible. Keeping them apart also means an operation
/// never appears in a tool listing, so an agent enumerating its capabilities
/// does not find one it could mistake for an action.
fn management_surface() -> ProviderRole {
    ProviderRole::ManagementSurface {
        operations: vec![ManagementOperation {
            name: crate::management::OPEN_TARGET.to_string(),
            // A query: it reports what authority exists and, when none does,
            // arranges for the user to be asked. It changes nothing on the
            // machine it is asked about.
            kind: ManagementOperationKind::Query,
        }],
        config_schema: json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false,
        }),
        observability: Vec::new(),
        identity_scope: vec![IdentityScope::Session, IdentityScope::Project],
    }
}

pub fn build(module_id: &str) -> ModuleManifest {
    ModuleManifest {
        module_id: module_id.to_string(),
        module_version: env!("CARGO_PKG_VERSION").to_string(),
        protocol_ver: PROTOCOL_VERSION,
        trust_tier: TrustTier::FirstParty,
        provides: vec![
            ProviderRole::ToolProvider {
                tools: vec![Tool {
                    name: BROWSER_STATUS.to_string(),
                    description: Some(
                        "Report the browser-plane session status and profile disposition \
                     without opening a browser."
                            .to_string(),
                    ),
                    execution_mode: ExecutionMode::Pure,
                    // Closed schema: the request is `{}` (empty); unknown fields are
                    // rejected at the application level. The schema declares no
                    // properties and forbids additional properties.
                    schema: json!({
                        "type": "object",
                        "properties": {},
                        "additionalProperties": false,
                    }),
                }],
                identity_scope: vec![IdentityScope::Session, IdentityScope::Project],
                concurrency: Concurrency::ModuleManaged,
                emits_push: false,
                sub_supervises: false,
            },
            management_surface(),
        ],
        consumes: Vec::new(),
        scheduled_tasks: Vec::new(),
        bindings: Bindings {
            // Spec A has no profile storage (Spec B owns that). The manifest enum
            // has no none/ephemeral storage kind yet, so this is the honest
            // expression: sqlite-scoped, but the module owns no schema and does
            // not open a database in this slice.
            storage: StorageBinding {
                kind: StorageKind::Sqlite,
                scope: StorageScope::Project,
                owns_schema: false,
            },
            vault_grants: Vec::new(),
            identity: IdentityBinding {
                requires: vec![IdentityScope::Project],
                optional: vec![IdentityScope::Session],
            },
        },
    }
}

/// Compose the six browser routes independently from the existing type route.
/// A common pin failure suppresses every minted route; an extraction failure
/// suppresses only routes that consume accessibility or DOM data (snapshot and
/// click).
pub fn build_with_browser_plane_pins(
    module_id: &str,
    pins: Option<&ManifestPinSet>,
    common_artifacts_eligible: bool,
    extraction_evidence_eligible: bool,
) -> ModuleManifest {
    let mut manifest = build(module_id);
    let Some(pins) = pins else {
        return manifest;
    };
    if pins.validate().is_err() || !common_artifacts_eligible {
        return manifest;
    }
    let ProviderRole::ToolProvider { tools, .. } = &mut manifest.provides[0] else {
        return manifest;
    };
    for (name, description, schema) in crate::browser::tool_definitions() {
        let requires_extraction = matches!(name, crate::browser::SNAPSHOT | crate::browser::CLICK);
        if requires_extraction
            && (!pins.extraction_group_eligible() || !extraction_evidence_eligible)
        {
            continue;
        }
        tools.push(Tool {
            name: name.to_string(),
            description: Some(description.to_string()),
            execution_mode: if matches!(
                name,
                crate::browser::NAVIGATE | crate::browser::CLICK | crate::browser::CLICK_POINT
            ) {
                ExecutionMode::Unfenceable
            } else {
                ExecutionMode::Pure
            },
            schema,
        });
    }
    manifest
}

/// Serialize the standard manifest and its single top-level browser-plane
/// extension for HELLO/release tooling. The external SUBC manifest type used by
/// status-only builds predates extensions, so composition is explicit here.
pub fn serialize_with_browser_plane_pins(
    module_id: &str,
    pins: Option<&ManifestPinSet>,
    common_artifacts_eligible: bool,
    extraction_evidence_eligible: bool,
) -> Value {
    let manifest = build_with_browser_plane_pins(
        module_id,
        pins,
        common_artifacts_eligible,
        extraction_evidence_eligible,
    );
    let mut value = serde_json::to_value(manifest).expect("module manifest serializes");
    if let Some(pins) = pins {
        if common_artifacts_eligible && pins.validate().is_ok() {
            let mut pin_value = serde_json::to_value(pins).expect("pins serialize");
            if !pins
                .browser_type_evidence_eligibility_sha256
                .as_deref()
                .is_some_and(custody::valid_digest)
            {
                pin_value
                    .as_object_mut()
                    .expect("pins are an object")
                    .remove("browser_type_evidence_eligibility_sha256");
            }
            value
                .as_object_mut()
                .expect("manifest is an object")
                .insert("browser_plane_pins".into(), pin_value);
        }
    }
    value
}

/// Evidence that the immutable B1 revision or contract-bundle vendors the B2A
/// journal pin exactly (`b1_journal_pin_compatibility_gate`).
///
/// A tokenless trait, a B1 revision that defines `journal_entry_oversize` as a
/// direct `reserve` result, or an implementation that invokes any journal
/// transition after a failed marked attempt is incompatible and keeps the
/// affected capability unadvertised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct B1PinCompatibility {
    /// The pinned immutable B1 revision or contract-bundle digest.
    pub revision_or_digest: String,
    /// Whether conformance proved every pin rule: invocation-bound reservation
    /// handles and commitment tokens, the exact `reserve` result set,
    /// post-reservation-only `journal_entry_oversize`, no invocation-side
    /// journal transition after a failed marked attempt (recovery-exclusive
    /// retry/cancellation), and matching-token `finalize_dispatched`.
    pub conformance_passed: bool,
}

/// The external manifest-bound inputs required to advertise one unfenceable
/// capability.
///
/// Each input is absent until bound at release time. Absence gates
/// advertisement (the capability stays unadvertised) but never blocks slice
/// implementation, and is reported distinctly from an implementation failure.
#[derive(Debug, Clone, Default)]
pub struct UnfenceableReleaseInputs {
    /// The browser evidence eligibility digests (manifest value, source lock,
    /// computed artifact).
    pub evidence: Option<EvidenceEligibilityInput>,
    /// The immutable B1 revision or contract-bundle digest satisfying the
    /// journal-pin compatibility gate.
    pub b1_pin: Option<B1PinCompatibility>,
    /// The positive journal deployment bounds.
    pub journal_bounds: Option<JournalConfig>,
    /// The computed maximum request-entry size for the capability
    /// (`computed_max_entry_bytes`).
    pub computed_max_entry_bytes: Option<u64>,
}

/// The outcome of evaluating one release gate.
///
/// A missing external input and an implementation failure are DIFFERENT facts
/// and never collapse into one outcome: the former means the gate could not be
/// evaluated because its external dependency is not bound; the latter means the
/// inputs were present but the implementation could not satisfy the gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateOutcome {
    /// The gate passed.
    Pass,
    /// A required external manifest-bound input is absent or incompatible.
    MissingInput { gate: &'static str },
    /// An implementation check ran against present inputs and failed.
    ImplementationFailure { gate: &'static str },
}

/// The B2A release report: the outcome of every gate evaluated for a surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseReport {
    pub outcomes: Vec<GateOutcome>,
}

impl ReleaseReport {
    /// Whether every gate passed (the surface may be advertised).
    pub fn passed(&self) -> bool {
        self.outcomes.iter().all(|o| matches!(o, GateOutcome::Pass))
    }

    /// The gates suppressed by a missing external input.
    pub fn missing_inputs(&self) -> Vec<&'static str> {
        self.outcomes
            .iter()
            .filter_map(|o| match o {
                GateOutcome::MissingInput { gate } => Some(*gate),
                _ => None,
            })
            .collect()
    }

    /// The gates suppressed by an implementation failure.
    pub fn implementation_failures(&self) -> Vec<&'static str> {
        self.outcomes
            .iter()
            .filter_map(|o| match o {
                GateOutcome::ImplementationFailure { gate } => Some(*gate),
                _ => None,
            })
            .collect()
    }
}

/// Evaluate every B2A release gate applicable to an unfenceable capability.
///
/// The browser evidence eligibility digest is ONE gate among several; it alone
/// never authorizes advertisement. Each gate reports a missing external input
/// distinctly from an implementation failure.
pub fn evaluate_unfenceable_gates(inputs: &UnfenceableReleaseInputs) -> ReleaseReport {
    let mut outcomes = Vec::new();

    // Gate: browser evidence eligibility (manifest value, source lock, computed
    // artifact all agree).
    outcomes.push(match &inputs.evidence {
        None => GateOutcome::MissingInput {
            gate: "browser_evidence",
        },
        Some(evidence) => {
            if browser_type_registration_eligible(evidence) {
                GateOutcome::Pass
            } else {
                GateOutcome::ImplementationFailure {
                    gate: "browser_evidence",
                }
            }
        }
    });

    // Gate: immutable B1 journal-pin compatibility.
    outcomes.push(match &inputs.b1_pin {
        None => GateOutcome::MissingInput {
            gate: "b1_journal_pin",
        },
        Some(pin) if !pin.revision_or_digest.is_empty() && pin.conformance_passed => {
            GateOutcome::Pass
        }
        Some(_) => GateOutcome::ImplementationFailure {
            gate: "b1_journal_pin",
        },
    });

    // Gate: positive, ordered journal deployment bounds.
    outcomes.push(match &inputs.journal_bounds {
        None => GateOutcome::MissingInput {
            gate: "journal_bounds",
        },
        Some(bounds) => {
            if bounds.validate().is_ok() {
                GateOutcome::Pass
            } else {
                GateOutcome::ImplementationFailure {
                    gate: "journal_bounds",
                }
            }
        }
    });

    // Gate: serialization fit (computed_max_entry_bytes <= journal_max_entry_bytes).
    outcomes.push(
        match (&inputs.computed_max_entry_bytes, &inputs.journal_bounds) {
            (Some(max), Some(bounds)) => {
                if *max <= bounds.journal_max_entry_bytes {
                    GateOutcome::Pass
                } else {
                    GateOutcome::ImplementationFailure {
                        gate: "serialization_fit",
                    }
                }
            }
            _ => GateOutcome::MissingInput {
                gate: "serialization_fit",
            },
        },
    );

    ReleaseReport { outcomes }
}

/// The evidence-gated manifest for `browser.type`, which production does not
/// build.
///
/// Advertising requires BOTH that the release gates pass AND that the capability
/// can be dispatched. The second condition is not redundant: the gates are
/// satisfied by supplying release evidence, which is a deployment act, while
/// being dispatchable is a property of the code. Without it, supplying evidence
/// alone would advertise a capability that every call to it rejects as an
/// unknown method — and this one accepts typed text, so the caller would be told
/// it has a facility for entering text that does not exist.
///
/// Today `browser.type` has no dispatch route, so this advertises nothing
/// whatever the evidence says. Adding one is what makes the gate live, which is
/// the point at which its evidence requirements have to be met rather than
/// merely defined.
pub fn build_with_unfenceable_evidence(inputs: &UnfenceableReleaseInputs) -> ModuleManifest {
    let mut manifest = build("cerebellum");
    if !evaluate_unfenceable_gates(inputs).passed() {
        return manifest;
    }
    if crate::dispatchable_tool(BROWSER_TYPE_TOOL).is_none() {
        return manifest;
    }
    let ProviderRole::ToolProvider { tools, .. } = &mut manifest.provides[0] else {
        return manifest;
    };
    tools.push(browser_type_tool());
    manifest
}

/// Construct the fixed `browser.type` tool definition that is added to the
/// manifest only after the eligibility checks have passed.
pub fn browser_type_tool() -> Tool {
    Tool {
        name: BROWSER_TYPE_TOOL.to_string(),
        description: Some(
            "Focus an eligible text target, optionally replace its selection, and insert literal text after two snapshot verifications."
                .to_string(),
        ),
        execution_mode: ExecutionMode::Unfenceable,
        schema: json!({
            "type": "object",
            "properties": {
                "ref": {"type": "string"},
                "snapshot_id": {"type": "string"},
                "text": {"type": "string"},
                "replace": {"type": "boolean"},
                "intent": {"type": "string"},
                "severity": {"type": "object"},
            },
            "required": ["ref", "snapshot_id", "text", "intent", "severity"],
            "additionalProperties": false,
        }),
    }
}

/// Return the manifest's immutable eligibility digest without exposing a
/// mutable approval or ambient registration switch.
pub fn browser_evidence_eligibility_sha256() -> &'static str {
    BROWSER_EVIDENCE_ELIGIBILITY_SHA256
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_advertises_exactly_one_capability() {
        let manifest = build("cerebellum");
        let ProviderRole::ToolProvider { tools, .. } = &manifest.provides[0] else {
            panic!("expected a ToolProvider role");
        };
        assert_eq!(tools.len(), 1, "exactly one application capability");
        assert_eq!(tools[0].name, BROWSER_STATUS);
    }

    /// The management surface advertises only what the dispatcher will serve.
    ///
    /// Both read one constant, so the two cannot drift: an operation added to
    /// this list without a route to serve it would have to be added to the
    /// routing as well, because there is only one name to add.
    ///
    /// The reverse case is what makes it worth asserting. A capability that is
    /// advertised and cannot be served fails at the moment a caller believes it
    /// can be, which is later and further from the change that caused it.
    #[test]
    fn every_advertised_operation_is_one_the_dispatcher_serves() {
        let manifest = build("cerebellum");
        let Some(ProviderRole::ManagementSurface { operations, .. }) = manifest
            .provides
            .iter()
            .find(|role| matches!(role, ProviderRole::ManagementSurface { .. }))
        else {
            panic!("expected a ManagementSurface role");
        };

        let advertised: Vec<&str> = operations
            .iter()
            .map(|operation| operation.name.as_str())
            .collect();
        assert_eq!(advertised, vec![crate::management::OPEN_TARGET]);
    }

    /// Opening a target is advertised as a query.
    ///
    /// It reports what authority exists and, when none does, arranges for the
    /// user to be asked. Nothing about the machine it names is changed, and the
    /// distinction is not cosmetic: whether a call is a query decides whether
    /// its response body is written to durable storage as it is forwarded.
    #[test]
    fn opening_a_target_is_a_query() {
        let manifest = build("cerebellum");
        let Some(ProviderRole::ManagementSurface { operations, .. }) = manifest
            .provides
            .iter()
            .find(|role| matches!(role, ProviderRole::ManagementSurface { .. }))
        else {
            panic!("expected a ManagementSurface role");
        };
        assert_eq!(operations[0].kind, ManagementOperationKind::Query);
    }

    #[test]
    fn browser_status_is_pure() {
        let manifest = build("cerebellum");
        let ProviderRole::ToolProvider { tools, .. } = &manifest.provides[0] else {
            panic!("expected a ToolProvider role");
        };
        assert_eq!(tools[0].execution_mode, ExecutionMode::Pure);
    }

    #[test]
    fn browser_status_schema_is_closed() {
        let manifest = build("cerebellum");
        let ProviderRole::ToolProvider { tools, .. } = &manifest.provides[0] else {
            panic!("expected a ToolProvider role");
        };
        let schema = &tools[0].schema;
        assert_eq!(schema.get("type").and_then(|v| v.as_str()), Some("object"));
        assert_eq!(
            schema.get("additionalProperties").and_then(|v| v.as_bool()),
            Some(false)
        );
    }

    #[test]
    fn manifest_protocol_version_is_v2() {
        let manifest = build("cerebellum");
        assert_eq!(manifest.protocol_ver, 2);
    }

    #[test]
    fn manifest_trust_tier_is_first_party() {
        let manifest = build("cerebellum");
        assert_eq!(manifest.trust_tier, TrustTier::FirstParty);
    }

    #[test]
    fn manifest_tool_schema_has_no_evidence_approval_member() {
        let manifest = build("cerebellum");
        let ProviderRole::ToolProvider { tools, .. } = &manifest.provides[0] else {
            panic!("expected a ToolProvider role");
        };
        assert!(tools[0]
            .schema
            .get("browser_evidence_eligibility_sha256")
            .is_none());
    }

    fn valid_evidence() -> EvidenceEligibilityInput {
        let digest = crate::browser_type::computed_eligibility_artifact_digest();
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

    fn valid_browser_pins(with_extraction: bool) -> ManifestPinSet {
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
        ManifestPinSet {
            schema: MANIFEST_PINS_SCHEMA.to_string(),
            spec_a_contract_sha256: digest.clone(),
            spec_b2_contract_bundle_sha256: digest.clone(),
            browser_custody_sha256: digest.clone(),
            browser_address_policy_sha256: digest.clone(),
            browser_connector_evidence_sha256: digest.clone(),
            browser_connector_runner_revision: "runner-v1".to_string(),
            browser_connector_test_plan_sha256: digest.clone(),
            browser_extraction_corpus_sha256: with_extraction.then(|| digest.clone()),
            browser_extraction_evidence_sha256: with_extraction.then(|| digest.clone()),
            browser_extraction_runner_revision: with_extraction.then(|| "extract-v1".to_string()),
            browser_type_evidence_eligibility_sha256: Some("not-a-digest".to_string()),
        }
    }

    #[test]
    fn browser_plane_routes_are_capability_relative_and_type_free() {
        let common_only = build_with_browser_plane_pins(
            "cerebellum",
            Some(&valid_browser_pins(false)),
            true,
            false,
        );
        let ProviderRole::ToolProvider { tools, .. } = &common_only.provides[0] else {
            panic!("expected tool provider");
        };
        assert_eq!(
            tools.len(),
            5,
            "status plus navigate, screenshot, point-click, and wait"
        );
        assert!(!tools.iter().any(|tool| tool.name == BROWSER_TYPE_TOOL));

        let all = build_with_browser_plane_pins(
            "cerebellum",
            Some(&valid_browser_pins(true)),
            true,
            true,
        );
        let ProviderRole::ToolProvider { tools, .. } = &all.provides[0] else {
            panic!("expected tool provider");
        };
        assert_eq!(tools.len(), 7, "status plus six minted browser routes");
        assert!(!tools.iter().any(|tool| tool.name == BROWSER_TYPE_TOOL));
        let serialized = serialize_with_browser_plane_pins(
            "cerebellum",
            Some(&valid_browser_pins(true)),
            true,
            true,
        );
        assert!(serialized.get("browser_plane_pins").is_some());
        assert!(serialized["provides"]
            .to_string()
            .find("browser_evidence_eligibility_sha256")
            .is_none());
    }

    fn has_browser_type(manifest: &ModuleManifest) -> bool {
        let ProviderRole::ToolProvider { tools, .. } = &manifest.provides[0] else {
            panic!("expected a ToolProvider role");
        };
        tools.iter().any(|tool| tool.name == BROWSER_TYPE_TOOL)
    }

    #[test]
    fn unfenceable_advertisement_requires_every_gate_to_pass() {
        // Every gate passing ADMITS browser.type, asserted through the gate
        // report. The manifest cannot carry the positive case: advertising also
        // requires a dispatch route, and browser.type has none, so reading the
        // manifest here would find it absent for that reason and hold however
        // the gates behaved.
        assert!(evaluate_unfenceable_gates(&valid_inputs()).passed());

        // Suppressing any single gate withholds admission. Also asserted
        // through the report rather than through the manifest: browser.type is
        // absent from the manifest whatever the gates say, so a manifest
        // assertion here would pass with the gate deleted.
        let mut no_evidence = valid_inputs();
        no_evidence.evidence = None;
        assert!(!evaluate_unfenceable_gates(&no_evidence).passed());

        let mut no_pin = valid_inputs();
        no_pin.b1_pin = None;
        assert!(!evaluate_unfenceable_gates(&no_pin).passed());

        let mut no_bounds = valid_inputs();
        no_bounds.journal_bounds = None;
        assert!(!evaluate_unfenceable_gates(&no_bounds).passed());

        let mut no_fit = valid_inputs();
        no_fit.computed_max_entry_bytes = None;
        assert!(!evaluate_unfenceable_gates(&no_fit).passed());

        // And the manifest carries none of it, on inputs that pass every gate,
        // so this fails when a dispatch route is added rather than silently
        // starting to advertise.
        assert!(!has_browser_type(&build_with_unfenceable_evidence(
            &valid_inputs()
        )));
    }

    #[test]
    fn digest_alone_never_authorizes_advertisement() {
        // The legacy eligibility-digest-only path is superseded: a valid browser
        // evidence artifact with no B1 pin, bounds, or fit input does NOT
        // advertise browser.type.
        let digest_only = UnfenceableReleaseInputs {
            evidence: Some(valid_evidence()),
            ..UnfenceableReleaseInputs::default()
        };
        assert!(!has_browser_type(&build_with_unfenceable_evidence(
            &digest_only
        )));
    }

    #[test]
    fn advertisement_suppressed_when_a_gate_fails() {
        // A present-but-incompatible B1 pin (conformance not proved) suppresses
        // advertisement and is reported as an implementation failure, not a
        // missing input.
        let mut failing_pin = valid_inputs();
        failing_pin.b1_pin = Some(B1PinCompatibility {
            revision_or_digest: "b1-rev-1".to_string(),
            conformance_passed: false,
        });
        assert!(!has_browser_type(&build_with_unfenceable_evidence(
            &failing_pin
        )));
        let report = evaluate_unfenceable_gates(&failing_pin);
        assert_eq!(report.implementation_failures(), vec!["b1_journal_pin"]);
        assert!(report.missing_inputs().is_empty());
    }

    #[test]
    fn release_report_distinguishes_missing_input_from_implementation_failure() {
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

        // The two outcomes are distinct variants for the same gate (index 1).
        assert_ne!(
            missing_report.outcomes[1], failed_report.outcomes[1],
            "missing input and implementation failure must be distinct outcomes"
        );
    }
}

// ---------------------------------------------------------------------------
// Browser-plane release pins: values that identify the exact contracts and
// policies used by the browser-facing execution plane.
// ---------------------------------------------------------------------------

/// The closed top-level browser-plane pin object. It is kept separate from
/// tool JSON schemas so release tooling and browser-facing protocol messages
/// serialize and reuse exactly the same pin bytes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestPinSet {
    pub schema: String,
    pub spec_a_contract_sha256: String,
    pub spec_b2_contract_bundle_sha256: String,
    pub browser_custody_sha256: String,
    pub browser_address_policy_sha256: String,
    pub browser_connector_evidence_sha256: String,
    pub browser_connector_runner_revision: String,
    pub browser_connector_test_plan_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_extraction_corpus_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_extraction_evidence_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_extraction_runner_revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_type_evidence_eligibility_sha256: Option<String>,
}

pub const MANIFEST_PINS_SCHEMA: &str = "ck-browser-plane-pins/v1";
pub type BrowserPlanePins = ManifestPinSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrozenTypeEvidenceStatus {
    Absent,
    Accepted,
    OmittedMalformed,
    OmittedMismatched,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestPinParseReport {
    pub frozen_type_evidence: FrozenTypeEvidenceStatus,
    pub messages: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedManifestPins {
    pub pins: ManifestPinSet,
    pub report: ManifestPinParseReport,
    pub canonical_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestPinError {
    InvalidJson,
    NonCanonical,
    UnknownField(String),
    MissingField(&'static str),
    InvalidField(&'static str),
}

impl ManifestPinSet {
    pub fn parse(
        bytes: &[u8],
        expected_frozen_type_digest: &str,
    ) -> Result<ParsedManifestPins, ManifestPinError> {
        parse_manifest_pins(bytes, expected_frozen_type_digest)
    }

    pub fn validate(&self) -> Result<(), ManifestPinError> {
        self.validate_common()
    }

    /// Validate fields that gate every minted capability. Extraction pins are
    /// checked separately because snapshot consumers may be suppressed while
    /// navigate, screenshot, click-point, and wait-for remain live.
    pub fn validate_common(&self) -> Result<(), ManifestPinError> {
        if self.schema != MANIFEST_PINS_SCHEMA {
            return Err(ManifestPinError::InvalidField("schema"));
        }
        for (name, value) in [
            ("spec_a_contract_sha256", &self.spec_a_contract_sha256),
            (
                "spec_b2_contract_bundle_sha256",
                &self.spec_b2_contract_bundle_sha256,
            ),
            ("browser_custody_sha256", &self.browser_custody_sha256),
            (
                "browser_address_policy_sha256",
                &self.browser_address_policy_sha256,
            ),
            (
                "browser_connector_evidence_sha256",
                &self.browser_connector_evidence_sha256,
            ),
            (
                "browser_connector_test_plan_sha256",
                &self.browser_connector_test_plan_sha256,
            ),
        ] {
            if !custody::valid_digest(value) {
                return Err(ManifestPinError::InvalidField(name));
            }
        }
        if !(1..=256).contains(&self.browser_connector_runner_revision.len())
            || matches!(
                self.browser_connector_runner_revision
                    .to_ascii_lowercase()
                    .as_str(),
                "placeholder" | "tbd" | "unknown"
            )
        {
            return Err(ManifestPinError::InvalidField(
                "browser_connector_runner_revision",
            ));
        }
        // The legacy type-route digest is optional and non-blocking. Invalid or
        // mismatched candidates are omitted by `parse_manifest_pins`; they never
        // gate a newly minted browser capability.
        Ok(())
    }

    /// Whether the extraction pins are present and usable as a group.
    ///
    /// The three are eligible together or not at all. A partly supplied group is
    /// refused for the same reason an absent one is, which is deliberate: the
    /// pins describe one artifact set, and two of three would gate a capability
    /// on evidence that does not cover it.
    pub fn extraction_group_eligible(&self) -> bool {
        let extraction = [
            self.browser_extraction_corpus_sha256.as_ref(),
            self.browser_extraction_evidence_sha256.as_ref(),
            self.browser_extraction_runner_revision.as_ref(),
        ];
        if extraction.iter().any(Option::is_none) {
            return false;
        }
        let (Some(corpus), Some(evidence), Some(revision)) = (
            self.browser_extraction_corpus_sha256.as_ref(),
            self.browser_extraction_evidence_sha256.as_ref(),
            self.browser_extraction_runner_revision.as_ref(),
        ) else {
            return false;
        };
        custody::valid_digest(corpus)
            && custody::valid_digest(evidence)
            && (1..=256).contains(&revision.len())
            && !matches!(
                revision.to_ascii_lowercase().as_str(),
                "placeholder" | "tbd" | "unknown"
            )
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        custody::canonical_json_bytes(&serde_json::to_value(self).expect("manifest pins serialize"))
    }
}

/// Parse a canonical pin object. The optional pin for the expected frozen
/// browser type is handled differently: if it is invalid or does not match the
/// expected digest, report and remove it instead of blocking a minted action.
///
/// The expected digest is required rather than optional. It was optional, and a
/// caller passing nothing got [`FrozenTypeEvidenceStatus::Accepted`] for any
/// well-formed digest -- a verified-looking answer produced without comparing
/// anything. A caller that does not know the value it expects is exactly the one
/// that must not be told the pin was accepted, and it can pass the digest it
/// believes correct to have that belief checked. Compare
/// [`browser_type::validate_evidence_eligibility`], which refuses outright when
/// a digest is missing.
pub fn parse_manifest_pins(
    bytes: &[u8],
    expected_frozen_type_digest: &str,
) -> Result<ParsedManifestPins, ManifestPinError> {
    let mut value: Value =
        serde_json::from_slice(bytes).map_err(|_| ManifestPinError::InvalidJson)?;
    if custody::canonical_json_bytes(&value) != bytes {
        return Err(ManifestPinError::NonCanonical);
    }
    let object = value.as_object_mut().ok_or(ManifestPinError::InvalidJson)?;
    let allowed = [
        "schema",
        "spec_a_contract_sha256",
        "spec_b2_contract_bundle_sha256",
        "browser_custody_sha256",
        "browser_address_policy_sha256",
        "browser_connector_evidence_sha256",
        "browser_connector_runner_revision",
        "browser_connector_test_plan_sha256",
        "browser_extraction_corpus_sha256",
        "browser_extraction_evidence_sha256",
        "browser_extraction_runner_revision",
        "browser_type_evidence_eligibility_sha256",
    ];
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(ManifestPinError::UnknownField(field.clone()));
    }
    let candidate = object
        .get("browser_type_evidence_eligibility_sha256")
        .cloned();
    let (status, message) = match candidate {
        None => (FrozenTypeEvidenceStatus::Absent, None),
        Some(Value::String(value))
            if custody::valid_digest(&value) && expected_frozen_type_digest == value =>
        {
            (FrozenTypeEvidenceStatus::Accepted, None)
        }
        Some(Value::String(_)) => {
            object.remove("browser_type_evidence_eligibility_sha256");
            (
                FrozenTypeEvidenceStatus::OmittedMismatched,
                Some("optional frozen-type evidence digest omitted: mismatch"),
            )
        }
        Some(_) => {
            object.remove("browser_type_evidence_eligibility_sha256");
            (
                FrozenTypeEvidenceStatus::OmittedMalformed,
                Some("optional frozen-type evidence digest omitted: malformed"),
            )
        }
    };
    let normalized_bytes = custody::canonical_json_bytes(&value);
    let pins: ManifestPinSet = serde_json::from_value(value).map_err(|error| {
        let text = error.to_string();
        if text.contains("missing field") {
            ManifestPinError::MissingField("browser_plane_pins")
        } else {
            ManifestPinError::InvalidField("browser_plane_pins")
        }
    })?;
    pins.validate()?;
    Ok(ParsedManifestPins {
        pins,
        report: ManifestPinParseReport {
            frozen_type_evidence: status,
            messages: message.into_iter().collect(),
        },
        canonical_bytes: normalized_bytes,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityGateInputs {
    pub common_artifacts_eligible: bool,
    pub extraction_evidence_eligible: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityEligibility {
    pub capability: &'static str,
    pub eligible: bool,
    pub requires_extraction: bool,
}

pub fn capability_relative_eligibility(
    pins: &ManifestPinSet,
    capability: &str,
    gates: CapabilityGateInputs,
) -> CapabilityEligibility {
    let requires_extraction = matches!(capability, "browser.snapshot" | "browser.click");
    let known = matches!(
        capability,
        "browser.navigate"
            | "browser.snapshot"
            | "browser.click"
            | "browser.screenshot"
            | "browser.click_point"
            | "browser.wait_for"
    );
    let eligible = known
        && pins.validate().is_ok()
        && gates.common_artifacts_eligible
        && (!requires_extraction
            || (pins.extraction_group_eligible() && gates.extraction_evidence_eligible));
    CapabilityEligibility {
        capability: match capability {
            "browser.navigate" => "browser.navigate",
            "browser.snapshot" => "browser.snapshot",
            "browser.click" => "browser.click",
            "browser.screenshot" => "browser.screenshot",
            "browser.click_point" => "browser.click_point",
            "browser.wait_for" => "browser.wait_for",
            _ => "",
        },
        eligible,
        requires_extraction,
    }
}

pub fn capability_is_eligible(
    pins: &ManifestPinSet,
    capability: &str,
    gates: CapabilityGateInputs,
) -> bool {
    capability_relative_eligibility(pins, capability, gates).eligible
}
