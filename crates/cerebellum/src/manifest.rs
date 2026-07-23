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

/// Build a release manifest with `browser.type` only when the manifest value,
/// source lock, and digest computed from the immutable eligibility artifact all
/// agree. This function checks only those three registration inputs; runtime
/// and packaging requirements are validated elsewhere.
pub fn build_with_browser_type_evidence(input: &EvidenceEligibilityInput) -> ModuleManifest {
    let mut manifest = build("cerebellum");
    if !browser_type_registration_eligible(input) {
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

    #[test]
    fn browser_type_registration_requires_all_three_digest_sources() {
        let digest = crate::browser_type::computed_eligibility_artifact_digest();
        let complete = EvidenceEligibilityInput {
            manifest_digest: Some(digest.clone()),
            source_lock_digest: Some(digest.clone()),
            computed_artifact_digest: Some(digest),
            ..EvidenceEligibilityInput::default()
        };
        let registered = build_with_browser_type_evidence(&complete);
        let ProviderRole::ToolProvider { tools, .. } = &registered.provides[0] else {
            panic!("expected a ToolProvider role");
        };
        assert!(tools.iter().any(|tool| tool.name == BROWSER_TYPE_TOOL));

        let manifest_only = EvidenceEligibilityInput {
            manifest_digest: Some(BROWSER_EVIDENCE_ELIGIBILITY_SHA256.to_string()),
            ..EvidenceEligibilityInput::default()
        };
        let rejected = build_with_browser_type_evidence(&manifest_only);
        let ProviderRole::ToolProvider { tools, .. } = &rejected.provides[0] else {
            panic!("expected a ToolProvider role");
        };
        assert!(!tools.iter().any(|tool| tool.name == BROWSER_TYPE_TOOL));
    }
}
