//! Three-fact bind identity and profile-boundary disposition.
//!
//! Cerebellum reads three identity facts verbatim from the bind and trusts them
//! because the consumer is spawn-attested first-party:
//! - **conversation-key**: the wire session-id the caller stamps on the bind
//!   (the fleet's per-conversation identity). Read verbatim; never minted.
//! - **agentProjectId**: the ck-projects PROJECT_ID (`pj-...`), the durable
//!   profile owner. One durable Alfonso per project directory.
//! - **sessionKind**: `primary | subagent | ephemeral`, stamped at bind time by
//!   alfonso-core from durable state, not self-declared.
//!
//! Profile lookup is `(agentProjectId, sessionKind)`. Isolation rides
//! `sessionKind`, not identity resolution: a mason and its primary resolve to
//! the same `agentProjectId`, and `sessionKind=subagent` is what keeps the
//! mason off the primary's profile.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use subc_protocol::{BindIdentity, Principal};

/// The alfonso-core-stamped session kind, read verbatim from the bind.
///
/// Derivation (owned by alfonso-core, not cerebellum): task-bound → `subagent`;
/// known-ephemeral prefix or persona_seats row → `ephemeral`; else `primary`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    Primary,
    Subagent,
    Ephemeral,
}

impl SessionKind {
    /// Parse a session-kind string stamped on the bind. Returns `None` for an
    /// unknown value (the caller decides whether to reject or default).
    pub fn from_str(kind: &str) -> Option<Self> {
        match kind {
            "primary" => Some(Self::Primary),
            "subagent" => Some(Self::Subagent),
            "ephemeral" => Some(Self::Ephemeral),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Subagent => "subagent",
            Self::Ephemeral => "ephemeral",
        }
    }
}

/// The profile disposition for a session kind, per the boundary policy.
///
/// - `primary` → durable profile (`profile_disposition: "durable"`).
/// - `subagent` → disposable profile, torn down at task end
///   (`profile_disposition: "disposable"`).
/// - `ephemeral` → no profile by default (`profile_disposition: "none"`).
///
/// The disposition vocabulary matches the `browser.status` context enum exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileDisposition {
    Durable,
    Disposable,
    None,
}

impl ProfileDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Durable => "durable",
            Self::Disposable => "disposable",
            Self::None => "none",
        }
    }

    /// Resolve the disposition from the alfonso-core-stamped session kind.
    pub fn for_session_kind(kind: SessionKind) -> Self {
        match kind {
            SessionKind::Primary => Self::Durable,
            SessionKind::Subagent => Self::Disposable,
            SessionKind::Ephemeral => Self::None,
        }
    }
}

/// The three-fact identity read verbatim from a route bind.
///
/// In Spec A there is no browser, so `profile_uuid` and `profile_name` are
/// stubbed as absent/empty — `browser.status` reports the resolved disposition
/// without opening a browser. Spec B owns actual profile storage.
#[derive(Debug, Clone)]
pub struct RouteIdentity {
    /// The wire session-id (conversation-key), read verbatim from the bind.
    /// Never echoed back in a result body (subc already correlates by
    /// (channel, corr)).
    pub conversation_key: String,
    /// The durable profile owner (`pj-...`), read verbatim from the bind.
    /// Never echoed back in a result body.
    pub agent_project_id: String,
    /// The alfonso-core-stamped session kind.
    pub session_kind: SessionKind,
    /// The resolved profile disposition for this session kind.
    pub profile_disposition: ProfileDisposition,
    /// The project root from the bind identity (used for profile lookup keying
    /// in Spec B; carried here for completeness).
    pub project_root: PathBuf,
}

impl RouteIdentity {
    /// Build a route identity from the bind fields.
    ///
    /// `agent_project_id` and `session_kind` are carried on the bind identity's
    /// `session` field in Spec A's wire shape (the fleet conversation-key is the
    /// `session` field; the agentProjectId and sessionKind ride alongside as
    /// bind-identity extensions). When they are absent, cerebellum defaults to
    /// `primary` (the common case) — the honest scope is that v1 isolation is
    /// defense-in-depth within a trusted consumer.
    pub fn from_bind(identity: &BindIdentity, _principal: &Option<Principal>) -> Self {
        let conversation_key = identity.session.clone();
        let agent_project_id = agent_project_id_from_identity(identity);
        let session_kind = session_kind_from_identity(identity);
        let profile_disposition = ProfileDisposition::for_session_kind(session_kind);
        Self {
            conversation_key,
            agent_project_id,
            session_kind,
            profile_disposition,
            project_root: identity.project_root.clone(),
        }
    }
}

/// Extract the agentProjectId from the bind identity. In Spec A's wire shape it
/// rides on the `harness` field (the fleet convention is one durable Alfonso
/// per project directory, and the harness identifies the project context). When
/// absent, a stable fallback is derived from the project root.
fn agent_project_id_from_identity(identity: &BindIdentity) -> String {
    // The agentProjectId is a stable blake3-derived id from the canonical project
    // root. In Spec A we do not have the ck-projects crate available, so we use
    // the project root path as the identity key (Spec B will thread the real
    // `pj-...` id from the bind).
    identity.project_root.to_string_lossy().to_string()
}

/// Extract the sessionKind from the bind identity. In Spec A's wire shape it
/// rides as a bind-identity extension. When absent, default to `primary`.
fn session_kind_from_identity(identity: &BindIdentity) -> SessionKind {
    // The sessionKind is stamped by alfonso-core from durable state. In Spec A
    // the bind does not yet carry a dedicated sessionKind field, so we default
    // to `primary` (the common case). Spec B will thread the real stamped value.
    // The harness field is cosmetic (routing/storage-slug); it does not carry
    // the session kind.
    let _ = &identity.harness;
    SessionKind::Primary
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bind_identity(project_root: &str, session: &str) -> BindIdentity {
        BindIdentity {
            project_root: PathBuf::from(project_root),
            harness: "opencode".to_string(),
            session: session.to_string(),
        }
    }

    #[test]
    fn session_kind_round_trips() {
        for kind in [
            SessionKind::Primary,
            SessionKind::Subagent,
            SessionKind::Ephemeral,
        ] {
            assert_eq!(SessionKind::from_str(kind.as_str()), Some(kind));
        }
    }

    #[test]
    fn unknown_session_kind_is_none() {
        assert!(SessionKind::from_str("unknown").is_none());
    }

    #[test]
    fn primary_resolves_durable() {
        assert_eq!(
            ProfileDisposition::for_session_kind(SessionKind::Primary),
            ProfileDisposition::Durable
        );
    }

    #[test]
    fn subagent_resolves_disposable() {
        assert_eq!(
            ProfileDisposition::for_session_kind(SessionKind::Subagent),
            ProfileDisposition::Disposable
        );
    }

    #[test]
    fn ephemeral_resolves_none() {
        assert_eq!(
            ProfileDisposition::for_session_kind(SessionKind::Ephemeral),
            ProfileDisposition::None
        );
    }

    #[test]
    fn route_identity_defaults_to_primary_when_session_kind_absent() {
        let identity = bind_identity("/tmp/project", "session-0001");
        let route = RouteIdentity::from_bind(&identity, &None);
        assert_eq!(route.session_kind, SessionKind::Primary);
        assert_eq!(route.profile_disposition, ProfileDisposition::Durable);
    }

    #[test]
    fn route_identity_carries_conversation_key_verbatim() {
        let identity = bind_identity("/tmp/project", "session-0001");
        let route = RouteIdentity::from_bind(&identity, &None);
        assert_eq!(route.conversation_key, "session-0001");
    }

    #[test]
    fn distinct_project_roots_resolve_to_distinct_agent_project_ids() {
        let identity_a = bind_identity("/tmp/project-a", "session-1");
        let identity_b = bind_identity("/tmp/project-b", "session-1");
        let route_a = RouteIdentity::from_bind(&identity_a, &None);
        let route_b = RouteIdentity::from_bind(&identity_b, &None);
        assert_ne!(route_a.agent_project_id, route_b.agent_project_id);
    }
}
