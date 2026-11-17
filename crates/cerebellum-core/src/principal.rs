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

/// Other daemon-spawned module ids trusted as first-party consumers of cerebellum
/// capabilities, alongside [`PREFRONTAL_MODULE_IDS`].
///
/// Membership is deliberately tight: a module belongs here only if driving
/// browser or computer use is part of its normal orchestration. The subc-mcp
/// facade only fronts remote-model calls, so it does not need these capabilities;
/// keeping it outside this list preserves it as the boundary around those calls.
///
/// Add a new id here before a module starts using it. The daemon refuses a
/// duplicate active id, so a rename has no window in which both names resolve:
/// the moment a module registers under a new id that this list doesn't name, it
/// loses access, and the failure shows up here as a permission refusal rather
/// than as a rename. Carry both the old and new ids across a rename, and drop
/// the old one only once no module registers under it.
pub(crate) const FIRST_PARTY_MODULE_IDS: &[&str] = &["striatum", "aft", "broca"];

/// The agent's orchestrator (prefrontal) registers as `prefrontal-core` today
/// and as `prefrontal` after its rename; both are accepted until the rename is
/// done everywhere. Remove `prefrontal-core` only once no orchestrator
/// registers under it.
pub const PREFRONTAL_MODULE_IDS: &[&str] = &["prefrontal-core", "prefrontal"];

/// Whether a reserved principal identifies the agent's orchestrator.
pub fn is_prefrontal(principal: &Principal) -> bool {
    matches!(principal, Principal::Reserved { module_id } if PREFRONTAL_MODULE_IDS.contains(&module_id.as_str()))
}

/// Identity projection for session scope owners across the orchestrator rename.
/// Keep the original owner in stored records and daemon requests; only keys and
/// comparisons use this projection.
pub fn canonical_scope_owner(owner: &Principal) -> Principal {
    if is_prefrontal(owner) {
        Principal::Reserved {
            module_id: "prefrontal".into(),
        }
    } else {
        owner.clone()
    }
}

/// Whether a daemon-spawned module id is a trusted first-party consumer of
/// cerebellum capabilities.
fn is_first_party_module_id(module_id: &str) -> bool {
    PREFRONTAL_MODULE_IDS.contains(&module_id) || FIRST_PARTY_MODULE_IDS.contains(&module_id)
}

/// The one module admitted to call cerebellum in a conversation's name.
///
/// Cerebellum's standing permissions (site grants, app grants, the takeover
/// grant) belong to the conversation a person gave them in. Every session's
/// browser and computer calls reach cerebellum through Prefrontal's forwarding
/// operations, so Prefrontal's core module is the only caller that may act
/// under a conversation. Any other first-party module (AFT, Broca, the routing
/// module, a `direct` host plugin) could otherwise open a route under a
/// conversation and act on the permissions given there without anyone being
/// asked.
///
/// Kept for callers that need to stamp a representative session caller. Admission
/// accepts every id in [`PREFRONTAL_MODULE_IDS`], not just this representative.
pub const SESSION_CALLER_MODULE_ID: &str = PREFRONTAL_MODULE_IDS[0];

/// The refusal code for a call that needs a conversation, made by a caller
/// not admitted to act in one.
pub const SESSION_CALLER_NOT_ADMITTED: &str = "session_caller_not_admitted";

/// What a caller refused with [`SESSION_CALLER_NOT_ADMITTED`] does next.
pub const SESSION_CALLER_NOT_ADMITTED_REMEDY: &str =
    "calls made in a conversation's name reach cerebellum only through Prefrontal's forwarding \
     operations; route this call through them. Only the operator's \
     own operations (browser.rebind_profile_root, browser.clear_launch_recovery, \
     computer.list_app_grants, computer.revoke_app_grant) are served to other callers, and \
     those run outside any conversation";

/// Whether a bind principal may make calls in a conversation's name.
///
/// Exact equality on the reserved module id: no prefix, suffix, case or
/// whitespace tolerance, since the daemon issues other reserved ids that
/// share a prefix with this one and a looser match would admit them.
pub fn admits_session_calls(principal: &Option<Principal>) -> bool {
    principal.as_ref().is_some_and(is_prefrontal)
}

/// A principal as the refusal messages name it: `reserved:<id>`, `direct`,
/// `unverified`, or `absent` when the daemon stamped none.
pub fn principal_label(principal: &Option<Principal>) -> String {
    match principal {
        Some(Principal::Reserved { module_id }) => format!("reserved:{module_id}"),
        Some(Principal::Direct) => "direct".to_string(),
        Some(Principal::Unverified) => "unverified".to_string(),
        None => "absent".to_string(),
    }
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
    fn retired_module_ids_are_untrusted() {
        assert_eq!(
            trust_for_principal(&Some(Principal::Reserved {
                module_id: "alfonso-core".to_string()
            })),
            PrincipalTrust::Untrusted
        );
    }

    /// Each module that depends on cerebellum is admitted, named by literal so
    /// that removing it from the list fails here.
    ///
    /// The ids are written out rather than iterated over
    /// [`FIRST_PARTY_MODULE_IDS`]: a loop over the list takes its expectations
    /// FROM the thing under test, so deleting an entry deletes its own check and
    /// could silently revoke that module's first-party admission.
    #[test]
    fn each_dependent_module_is_admitted() {
        for module_id in ["prefrontal-core", "striatum", "aft", "broca"] {
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

    fn reserved(module_id: &str) -> Option<Principal> {
        Some(Principal::Reserved {
            module_id: module_id.to_string(),
        })
    }

    #[test]
    fn prefrontal_aliases_require_reserved_principals() {
        for (principal, admitted) in [
            (reserved("prefrontal-core"), true),
            (reserved("prefrontal"), true),
            (reserved("prefrontal-corex"), false),
            (Some(Principal::Unverified), false),
            (Some(Principal::Direct), false),
            (None, false),
        ] {
            assert_eq!(
                principal.as_ref().is_some_and(is_prefrontal),
                admitted,
                "{principal:?}"
            );
        }
    }

    #[test]
    fn prefrontal_aliases_have_first_party_trust() {
        for (principal, trusted) in [
            (reserved("prefrontal-core"), true),
            (reserved("prefrontal"), true),
            (reserved("prefrontal-corex"), false),
            (Some(Principal::Unverified), false),
            (None, false),
        ] {
            assert_eq!(
                trust_for_principal(&principal).is_first_party(),
                trusted,
                "{principal:?}"
            );
        }
    }

    #[test]
    fn prefrontal_aliases_admit_session_calls() {
        for (principal, admitted) in [
            (reserved("prefrontal-core"), true),
            (reserved("prefrontal"), true),
            (reserved("prefrontal-corex"), false),
            (Some(Principal::Unverified), false),
            (Some(Principal::Direct), false),
            (None, false),
        ] {
            assert_eq!(admits_session_calls(&principal), admitted, "{principal:?}");
        }
    }

    #[test]
    fn only_prefrontal_core_makes_session_calls() {
        assert!(admits_session_calls(&reserved("prefrontal-core")));
    }

    /// Other first-party principals cannot make session calls, and retired
    /// module ids are neither first-party nor admitted. Named by literal so that
    /// widening the rule back to "any first-party principal" fails here.
    #[test]
    fn other_first_party_principals_make_no_session_calls() {
        for retired_id in ["alfonso-core", "alfonso-routing", "prefrontal-routing"] {
            assert_eq!(
                trust_for_principal(&reserved(retired_id)),
                PrincipalTrust::Untrusted,
                "{retired_id} is retired and must not remain first-party"
            );
            assert!(!admits_session_calls(&reserved(retired_id)));
        }

        let others = [
            Some(Principal::Direct),
            reserved("aft"),
            reserved("broca"),
            reserved("striatum"),
        ];
        for principal in others {
            assert!(trust_for_principal(&principal).is_first_party());
            assert!(
                !admits_session_calls(&principal),
                "{} is admitted to act in a conversation",
                principal_label(&principal)
            );
        }
    }

    /// Ids that differ from the admitted one by a character, a case, a
    /// trailing space or an affix are refused: the match is exact.
    #[test]
    fn ids_resembling_the_session_caller_make_no_session_calls() {
        for module_id in [
            "prefrontal-cor",
            "prefrontal-core-x",
            "Prefrontal-Core",
            "PREFRONTAL-CORE",
            "prefrontal-core ",
            " prefrontal-core",
            "prefrontal-core\0",
            "xprefrontal-core",
            "prefrontal-host:prefrontal-core",
            "",
        ] {
            assert!(
                !admits_session_calls(&reserved(module_id)),
                "{module_id:?} resembles the session caller but is not it"
            );
        }
    }

    #[test]
    fn untrusted_and_absent_principals_make_no_session_calls() {
        assert!(!admits_session_calls(&reserved("subc-mcp")));
        assert!(!admits_session_calls(&Some(Principal::Unverified)));
        assert!(!admits_session_calls(&None));
    }
}
