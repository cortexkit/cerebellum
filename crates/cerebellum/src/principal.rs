//! Principal default-deny backstop.
//!
//! The subc-mcp gateway policy is the PRIMARY exclusion of cerebellum
//! capabilities from `mcp:*` surfaces (configured in subc.jsonc, not here). This
//! module is the defense-in-depth BACKSTOP: it rejects a forged direct dispatch
//! under a non-first-party principal before any capability executes.
//!
//! First-party principals are spawn-attested `Reserved{module_id}` binds from
//! trusted fleet modules, plus `Direct` binds (host-launched key-holders like
//! the opencode plugin). `mcp:*` binds arrive as `Reserved{subc-mcp}` and are
//! untrusted — the facade is the remote-model choke point.

use subc_protocol::Principal;

/// The trust classification for a bind principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalTrust {
    /// A spawn-attested first-party consumer (trusted fleet module or direct
    /// key-holder). Gets capability-scoped access.
    FirstParty,
    /// An untrusted consumer (the subc-mcp facade, an unverified principal, or
    /// a missing principal). Gets no cerebellum capability.
    Untrusted,
}

impl PrincipalTrust {
    pub fn is_first_party(self) -> bool {
        matches!(self, Self::FirstParty)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::FirstParty => "first_party",
            Self::Untrusted => "untrusted",
        }
    }
}

/// Map a stamped bind principal to a trust classification.
///
/// This mirrors AFT's policy mapping (docs/subc-principal.md §3):
/// - `Direct` → trusted (first-party host plugins).
/// - `Reserved{module_id}` → per-id allowlist over daemon-spawned, spawn-
///   attested module ids. Trusted: alfonso-core, alfonso-routing, aft, broca,
///   and other first-party fleet modules. Untrusted: subc-mcp (the facade is
///   the remote-model choke point → containment).
/// - `Unverified` → fail-closed (defensive backstop).
/// - principal ABSENT → untrusted (a daemon bug that fails to stamp must not
///   silently grant trust).
pub fn trust_for_principal(principal: &Option<Principal>) -> PrincipalTrust {
    match principal {
        Some(Principal::Direct) => PrincipalTrust::FirstParty,
        Some(Principal::Reserved { module_id }) => {
            if is_first_party_module_id(module_id) {
                PrincipalTrust::FirstParty
            } else {
                PrincipalTrust::Untrusted
            }
        }
        Some(Principal::Unverified) | None => PrincipalTrust::Untrusted,
    }
}

/// Whether a daemon-spawned module id is a trusted first-party consumer of
/// cerebellum capabilities.
///
/// The allowlist is deliberately tight: only the fleet modules that drive
/// browser/computer use as part of their normal orchestration. The subc-mcp
/// facade (`subc-mcp`) is explicitly excluded — it fronts remote-model calls
/// and is the containment boundary.
fn is_first_party_module_id(module_id: &str) -> bool {
    matches!(
        module_id,
        "alfonso-core" | "alfonso-routing" | "aft" | "broca"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_is_first_party() {
        assert_eq!(
            trust_for_principal(&Some(Principal::Direct)),
            PrincipalTrust::FirstParty
        );
    }

    #[test]
    fn alfonso_core_is_first_party() {
        assert_eq!(
            trust_for_principal(&Some(Principal::Reserved {
                module_id: "alfonso-core".to_string()
            })),
            PrincipalTrust::FirstParty
        );
    }

    #[test]
    fn subc_mcp_is_untrusted() {
        assert_eq!(
            trust_for_principal(&Some(Principal::Reserved {
                module_id: "subc-mcp".to_string()
            })),
            PrincipalTrust::Untrusted
        );
    }

    #[test]
    fn unverified_is_untrusted() {
        assert_eq!(
            trust_for_principal(&Some(Principal::Unverified)),
            PrincipalTrust::Untrusted
        );
    }

    #[test]
    fn absent_principal_is_untrusted() {
        assert_eq!(trust_for_principal(&None), PrincipalTrust::Untrusted);
    }

    #[test]
    fn unknown_reserved_module_is_untrusted() {
        assert_eq!(
            trust_for_principal(&Some(Principal::Reserved {
                module_id: "unknown-module".to_string()
            })),
            PrincipalTrust::Untrusted
        );
    }
}
