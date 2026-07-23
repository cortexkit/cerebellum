//! Capability manifest for ck-cerebellum.
//!
//! Spec A advertises exactly one application capability, `browser.status`, with
//! `execution_mode: pure`. Standard wire-v2 health, discovery, and control
//! surfaces (route.bind, route.status, health.check) are NOT application
//! capabilities — they are advertised in the HELLO `control_ops` grant, not in
//! the manifest's `provides` list.

use serde_json::json;
use subc_protocol::manifest::{
    Bindings, Concurrency, ExecutionMode, IdentityBinding, IdentityScope, ModuleManifest,
    ProviderRole, StorageBinding, StorageKind, StorageScope, Tool, TrustTier,
};
use subc_protocol::PROTOCOL_VERSION;

/// The single application capability this module advertises.
pub const BROWSER_STATUS: &str = "browser.status";

/// Build the cerebellum capability manifest.
///
/// The manifest declares exactly one `ToolProvider` role with exactly one tool
/// (`browser.status`, `execution_mode: pure`). There is no browser, no CDP, and
/// no profile storage in Spec A — `browser.status` reports profile disposition
/// without opening a browser, so it produces no observable side effect and is
/// honestly classified `pure`.
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
}
