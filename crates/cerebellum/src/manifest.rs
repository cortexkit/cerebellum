//! Capability manifest for ck-cerebellum.
//!
//! Spec A advertises exactly one application capability, `browser.status`, with
//! `execution_mode: pure`. Standard wire-v2 health, discovery, and control
//! surfaces (route.bind, route.status, health.check) are NOT application
//! capabilities — they are advertised in the HELLO `control_ops` grant, not in
//! the manifest's `provides` list.

use serde_json::json;

use crate::browser_type::{
    browser_type_registration_eligible, EvidenceEligibilityInput,
    BROWSER_EVIDENCE_ELIGIBILITY_SHA256, BROWSER_TYPE_TOOL,
};
use crate::journal::JournalConfig;
use subc_protocol::manifest::{
    Bindings, Concurrency, ExecutionMode, IdentityBinding, IdentityScope, ModuleManifest,
    ProviderRole, StorageBinding, StorageKind, StorageScope, Tool, TrustTier,
};
use subc_protocol::PROTOCOL_VERSION;

/// The single application capability this module advertises.
pub const BROWSER_STATUS: &str = "browser.status";

/// Build the browser-free cerebellum capability manifest.
///
/// The manifest declares exactly one `ToolProvider` role with exactly one tool
/// (`browser.status`, `execution_mode: pure`). Register `browser.type` only
/// when its manifest value, locked source revision, and SHA-256 digest of the
/// immutable eligibility artifact match the expected values. This prevents a
/// dependency bundle from authorizing registration without matching source
/// evidence.
pub fn build(module_id: &str) -> ModuleManifest {
    ModuleManifest {
        module_id: module_id.to_string(),
        module_version: env!("CARGO_PKG_VERSION").to_string(),
        protocol_ver: PROTOCOL_VERSION,
        trust_tier: TrustTier::FirstParty,
        provides: vec![ProviderRole::ToolProvider {
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
                    "browser_evidence_eligibility_sha256":
                        BROWSER_EVIDENCE_ELIGIBILITY_SHA256,
                }),
            }],
            identity_scope: vec![IdentityScope::Session, IdentityScope::Project],
            concurrency: Concurrency::ModuleManaged,
            emits_push: false,
            sub_supervises: false,
        }],
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

/// Build a release manifest, adding `browser.type` ONLY when every applicable
/// B2A release gate passes.
///
/// This supersedes the legacy eligibility-digest-only manifest path: the browser
/// evidence or eligibility digest alone never authorizes advertisement. With the
/// evidence artifact valid but the B1 pin absent, the journal bounds absent, or
/// any required gate failed, `browser.type` is absent and externally
/// non-invocable.
pub fn build_with_unfenceable_evidence(inputs: &UnfenceableReleaseInputs) -> ModuleManifest {
    let mut manifest = build("cerebellum");
    let report = evaluate_unfenceable_gates(inputs);
    if !report.passed() {
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
            "browser_evidence_eligibility_sha256":
                BROWSER_EVIDENCE_ELIGIBILITY_SHA256,
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
        assert_eq!(manifest.provides.len(), 1);
        let ProviderRole::ToolProvider { tools, .. } = &manifest.provides[0] else {
            panic!("expected a ToolProvider role");
        };
        assert_eq!(tools.len(), 1, "exactly one application capability");
        assert_eq!(tools[0].name, BROWSER_STATUS);
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
    fn manifest_carries_computed_eligibility_digest() {
        let manifest = build("cerebellum");
        let ProviderRole::ToolProvider { tools, .. } = &manifest.provides[0] else {
            panic!("expected a ToolProvider role");
        };
        assert_eq!(
            tools[0].schema["browser_evidence_eligibility_sha256"],
            BROWSER_EVIDENCE_ELIGIBILITY_SHA256
        );
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

    fn has_browser_type(manifest: &ModuleManifest) -> bool {
        let ProviderRole::ToolProvider { tools, .. } = &manifest.provides[0] else {
            panic!("expected a ToolProvider role");
        };
        tools.iter().any(|tool| tool.name == BROWSER_TYPE_TOOL)
    }

    #[test]
    fn unfenceable_advertisement_requires_every_gate_to_pass() {
        // All gates pass: browser.type is advertised.
        assert!(has_browser_type(&build_with_unfenceable_evidence(
            &valid_inputs()
        )));

        // Suppressing any single gate keeps browser.type absent.
        let mut no_evidence = valid_inputs();
        no_evidence.evidence = None;
        assert!(!has_browser_type(&build_with_unfenceable_evidence(
            &no_evidence
        )));

        let mut no_pin = valid_inputs();
        no_pin.b1_pin = None;
        assert!(!has_browser_type(&build_with_unfenceable_evidence(&no_pin)));

        let mut no_bounds = valid_inputs();
        no_bounds.journal_bounds = None;
        assert!(!has_browser_type(&build_with_unfenceable_evidence(
            &no_bounds
        )));

        let mut no_fit = valid_inputs();
        no_fit.computed_max_entry_bytes = None;
        assert!(!has_browser_type(&build_with_unfenceable_evidence(&no_fit)));
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
