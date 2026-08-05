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
///   attested module ids; see [`is_first_party_module_id`] for the ids
///   themselves. Untrusted: subc-mcp (the facade is the remote-model choke
///   point → containment).
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

/// The daemon-spawned module ids trusted as first-party consumers of cerebellum
/// capabilities.
///
/// Membership is deliberately tight: a module belongs here only if driving
/// browser or computer use is part of its normal orchestration. The subc-mcp
/// facade is excluded by that rule rather than by exception — it fronts
/// remote-model calls and is the containment boundary.
///
/// An id is added BEFORE the module starts using it. The daemon keys modules by
/// id and refuses a duplicate active id, so a rename is a flag day with no
/// window in which both names resolve: the moment a module registers under a new
/// id, a list still naming only the old one classifies it as untrusted and
/// revokes its access. That failure is safe but silent, and it presents as a
/// permission fault here rather than as a rename elsewhere. Both names are
/// therefore carried across a rename, and the old one is dropped once the flip
/// has settled.
pub(crate) const FIRST_PARTY_MODULE_IDS: &[&str] = &[
    // The agent orchestrator, being renamed `alfonso-core` -> `prefrontal-core`.
    // Bare `prefrontal` is a spelling no module registers under, kept only until
    // the rename settles. An unused id authorizes nobody, because the daemon
    // issues a reserved principal only for a module it supervises -- so confirm
    // against the daemon's list of live modules before removing any of these.
    "alfonso-core",
    "prefrontal",
    "prefrontal-core",
    // The routing module, renamed in the same flip.
    "alfonso-routing",
    "prefrontal-routing",
    "aft",
    "broca",
];

/// Whether a daemon-spawned module id is a trusted first-party consumer of
/// cerebellum capabilities.
fn is_first_party_module_id(module_id: &str) -> bool {
    FIRST_PARTY_MODULE_IDS.contains(&module_id)
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

    /// Each module that depends on cerebellum is admitted, named by literal so
    /// that removing it from the list fails here.
    ///
    /// The ids are written out rather than iterated over
    /// [`FIRST_PARTY_MODULE_IDS`]: a loop over the list takes its expectations
    /// FROM the thing under test, so deleting an entry deletes its own check and
    /// the silent revocation this test exists to catch passes. Measured, not
    /// assumed -- an iterating version stayed green for three of the five ids.
    ///
    /// The orchestrator and the routing module each appear under both their old
    /// and new ids because they are mid-rename; the old ids are removed here
    /// when they are removed from the list.
    #[test]
    fn each_dependent_module_is_admitted() {
        for module_id in [
            "alfonso-core",
            "prefrontal",
            "prefrontal-core",
            "alfonso-routing",
            "prefrontal-routing",
            "aft",
            "broca",
        ] {
            assert_eq!(
                trust_for_principal(&Some(Principal::Reserved {
                    module_id: module_id.to_string()
                })),
                PrincipalTrust::FirstParty,
                "{module_id} depends on cerebellum but was not admitted"
            );
        }
    }

    /// The list and the admission predicate agree, so an id can never be listed
    /// as trusted while being refused in practice.
    #[test]
    fn every_listed_id_is_admitted() {
        assert!(
            !FIRST_PARTY_MODULE_IDS.is_empty(),
            "an empty list would satisfy this test vacuously"
        );
        for module_id in FIRST_PARTY_MODULE_IDS {
            assert_eq!(
                trust_for_principal(&Some(Principal::Reserved {
                    module_id: (*module_id).to_string()
                })),
                PrincipalTrust::FirstParty,
                "{module_id} is listed as first-party but was not admitted"
            );
        }
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

    /// Ids that RESEMBLE a trusted one are refused, because membership is exact
    /// string equality rather than a prefix, suffix, or substring relation.
    ///
    /// Refusing an unrelated id like `unknown-module` does not establish that:
    /// it fails every matching rule alike. Only a near-miss separates equality
    /// from the looser rules someone reaches for while a family of names is in
    /// flux -- and one of these near-misses is real, since the daemon issues
    /// host-bridge principals as `prefrontal-host:<provider-id>`, a
    /// first-party-looking prefix whose suffix the caller supplies. A prefix
    /// match would admit an unbounded set of ids nobody reviewed.
    #[test]
    fn ids_resembling_a_trusted_module_are_untrusted() {
        for module_id in [
            // Shares a prefix with the orchestrator; the suffix varies per
            // caller.
            "prefrontal-host:abc123",
            // Extends a trusted id.
            "prefrontal-core-evil",
            "aft-shim",
            // Is extended BY a trusted id.
            "prefront",
            "af",
            // Contains a trusted id without being one.
            "not-prefrontal-core",
            "evil-aft",
            // Differs from a trusted id only in content a comparison might
            // normalize away.
            "prefrontal-core ",
            "prefrontal-core\0",
            "PREFRONTAL-CORE",
            "",
        ] {
            assert_eq!(
                trust_for_principal(&Some(Principal::Reserved {
                    module_id: module_id.to_string()
                })),
                PrincipalTrust::Untrusted,
                "{module_id:?} resembles a trusted id but is not one"
            );
        }
    }
}
