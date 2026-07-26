//! Identity facts accepted on a route bind and the profile-boundary policy.
//!
//! Cerebellum consumes identity from the daemon-accepted bind facts. It does not
//! inspect tool request bodies for identity and it does not mint identity:
//! - **conversation-key** is the wire session id from `BindIdentity::session`.
//! - **agentProjectId** and **sessionKind** are stamped admission facts.
//! - **principal** is the daemon-stamped bind fact.
//! - **effective capability scope** is the admitted capability scope.
//!
//! Profile resolution is policy only. This module intentionally does not open a
//! browser, a profile registry, or profile storage.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use subc_protocol::{BindIdentity, Principal};

/// The alfonso-core-stamped session kind, read verbatim from the bind facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    Primary,
    Subagent,
    Ephemeral,
}

impl SessionKind {
    /// Parse a session-kind string stamped on the bind. Returns `None` for an
    /// unknown value; callers can choose a fail-closed or compatibility policy.
    #[allow(clippy::should_implement_trait)]
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

    pub fn for_session_kind(kind: SessionKind) -> Self {
        match kind {
            SessionKind::Primary => Self::Durable,
            SessionKind::Subagent => Self::Disposable,
            SessionKind::Ephemeral => Self::None,
        }
    }
}

/// The logical key used by the future profile-storage slice.
///
/// The key is deliberately a value type rather than a handle to storage. The
/// identity slice only computes this key; it never resolves or opens a profile.
pub type LogicalProfileKey = (String, String);

/// The result of the profile-boundary policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileResolution {
    pub profile_disposition: ProfileDisposition,
    pub profile_name: Option<String>,
    pub logical_profile_key: Option<LogicalProfileKey>,
}

impl ProfileResolution {
    fn for_identity(
        identity: &RouteIdentity,
        logical_profile_key: Option<LogicalProfileKey>,
    ) -> Self {
        match identity.session_kind {
            SessionKind::Primary => Self {
                profile_disposition: ProfileDisposition::Durable,
                profile_name: Some("default".to_string()),
                logical_profile_key,
            },
            SessionKind::Subagent => Self {
                profile_disposition: ProfileDisposition::Disposable,
                profile_name: Some("default".to_string()),
                logical_profile_key,
            },
            SessionKind::Ephemeral => Self {
                profile_disposition: ProfileDisposition::None,
                profile_name: None,
                logical_profile_key: None,
            },
        }
    }
}

/// The three identity facts read from a route bind, plus the resolved
/// disposition used by capability policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteIdentity {
    /// The wire session-id (conversation-key), read verbatim from the bind.
    pub conversation_key: String,
    /// The durable profile owner, read verbatim from accepted bind facts.
    pub agent_project_id: String,
    /// The alfonso-core-stamped session kind.
    pub session_kind: SessionKind,
    /// The resolved profile disposition for this session kind.
    pub profile_disposition: ProfileDisposition,
    /// The project root remains available as routing metadata, but is not used
    /// when an admitted agentProjectId is present.
    pub project_root: PathBuf,
}

impl RouteIdentity {
    /// Build identity from a bind without admission extensions.
    ///
    /// This compatibility constructor supports older wire fixtures that do not
    /// include daemon-accepted admission facts. New route handling should use
    /// [`Self::from_accepted_bind`], which consumes those facts.
    pub fn from_bind(identity: &BindIdentity, principal: &Option<Principal>) -> Self {
        Self::from_accepted_bind(identity, principal, None)
    }

    /// Read identity from the accepted bind facts. `admission_facts` is already
    /// carried by the daemon's `route.bind`; tool request bodies are not involved.
    pub fn from_accepted_bind(
        identity: &BindIdentity,
        _principal: &Option<Principal>,
        admission_facts: Option<&Value>,
    ) -> Self {
        let conversation_key = identity.session.clone();
        let agent_project_id = agent_project_id_from_facts(identity, admission_facts);
        let session_kind = session_kind_from_facts(admission_facts);
        let profile_disposition = ProfileDisposition::for_session_kind(session_kind);
        Self {
            conversation_key,
            agent_project_id,
            session_kind,
            profile_disposition,
            project_root: identity.project_root.clone(),
        }
    }

    /// Compute the logical profile key without opening profile storage.
    pub fn logical_profile_key(&self) -> Option<LogicalProfileKey> {
        match self.session_kind {
            SessionKind::Primary => Some((self.agent_project_id.clone(), "default".to_string())),
            SessionKind::Subagent => {
                Some((self.agent_project_id.clone(), self.conversation_key.clone()))
            }
            SessionKind::Ephemeral => None,
        }
    }

    /// Resolve the logical profile boundary without opening profile storage.
    pub fn resolve_profile(&self) -> ProfileResolution {
        let logical_profile_key = self.logical_profile_key();
        #[cfg(any(test, feature = "test-observer"))]
        record_test_observation(self, logical_profile_key.clone());
        ProfileResolution::for_identity(self, logical_profile_key)
    }
}

/// Facts retained after a route bind has passed principal admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedBindFacts {
    pub identity: RouteIdentity,
    pub principal: Option<Principal>,
    /// `None` means the legacy bind had no explicit scope and receives the
    /// module's first-party default. `Some(empty)` is an explicitly empty scope.
    pub effective_capability_scope: Option<Vec<String>>,
}

impl AcceptedBindFacts {
    pub fn from_bind(
        identity: &BindIdentity,
        principal: Option<Principal>,
        admission_facts: Option<&Value>,
    ) -> Self {
        Self {
            identity: RouteIdentity::from_accepted_bind(identity, &principal, admission_facts),
            principal,
            effective_capability_scope: effective_capability_scope_from_facts(admission_facts),
        }
    }

    /// Whether the accepted scope permits a capability. This uses only facts
    /// retained from `route.bind`; callers cannot widen it through a request.
    pub fn allows_capability(&self, capability: &str) -> bool {
        let Some(scope) = &self.effective_capability_scope else {
            return true;
        };
        scope.iter().any(|entry| {
            entry == "*"
                || entry == capability
                || (entry.ends_with(":*") && capability.starts_with(&entry[..entry.len() - 1]))
        })
    }
}

fn admission_object(facts: Option<&Value>) -> Option<&serde_json::Map<String, Value>> {
    let root = facts?.as_object()?;
    Some(root)
}

/// Look up a fact using the fleet's camelCase spelling and the Rust-facing
/// snake_case spelling. The small set of nested containers keeps the parser
/// tolerant of the carrier envelope while avoiding any request-body fallback.
fn fact<'a>(facts: Option<&'a Value>, names: &[&str]) -> Option<&'a Value> {
    let root = admission_object(facts)?;
    let containers = std::iter::once(root).chain(
        ["accepted", "bind", "bind_identity", "identity"]
            .into_iter()
            .filter_map(|name| root.get(name).and_then(Value::as_object)),
    );
    for object in containers {
        for name in names {
            if let Some(value) = object.get(*name) {
                return Some(value);
            }
        }
    }
    None
}

fn agent_project_id_from_facts(identity: &BindIdentity, facts: Option<&Value>) -> String {
    fact(
        facts,
        &[
            "agentProjectId",
            "agent_project_id",
            "projectId",
            "project_id",
        ],
    )
    .and_then(Value::as_str)
    .filter(|value| !value.is_empty())
    .map(ToOwned::to_owned)
    // Old wire fixtures predate the admitted project id. Keeping a stable
    // project-root fallback preserves those fixtures; admitted facts always win.
    //
    // SAFETY OF THIS FALLBACK IS NOT LOCAL. `project_root` arrives in
    // `BindIdentity`, which the daemon relays verbatim from the caller, so a
    // substituted value is caller-chosen rather than attested. What keeps that
    // out of durable storage is that both durable paths refuse a bind whose
    // facts are not daemon-attested BEFORE reading this field:
    // `profile::StampedBindContext::validate` and `journal_pin`'s
    // `validate_bind_facts` each require attested provenance and a present
    // `agent_project_id`, with no substitution of their own. This value
    // therefore reaches only policy resolution that opens no profile storage.
    // Extending a compatibility path to durable state means reproducing those
    // refusals, not reusing this fallback.
    .unwrap_or_else(|| identity.project_root.to_string_lossy().into_owned())
}

fn session_kind_from_facts(facts: Option<&Value>) -> SessionKind {
    // An absent kind resolves to the MOST privileged one, since `Primary` is the
    // kind that owns a durable profile. That is safe only on this path, and only
    // for the reason given above `agent_project_id_from_facts`: the durable
    // validators require a present, attested `session_kind` and refuse rather
    // than defaulting, so a defaulted kind never selects durable storage.
    fact(facts, &["sessionKind", "session_kind"])
        .and_then(Value::as_str)
        .and_then(SessionKind::from_str)
        .unwrap_or(SessionKind::Primary)
}

fn effective_capability_scope_from_facts(facts: Option<&Value>) -> Option<Vec<String>> {
    let value = fact(
        facts,
        &[
            "effectiveCapabilityScope",
            "effective_capability_scope",
            "capabilityScope",
            "capability_scope",
        ],
    )?;
    if let Some(scope) = value.as_str() {
        return Some(vec![scope.to_string()]);
    }
    if let Some(scope) = value.as_array() {
        return Some(
            scope
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect(),
        );
    }
    let object = value.as_object()?;
    ["capabilities", "allowed", "tools"]
        .iter()
        .find_map(|key| object.get(*key))
        .and_then(Value::as_array)
        .map(|scope| {
            scope
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
}

#[cfg(any(test, feature = "test-observer"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityResolutionObservation {
    pub conversation_key: String,
    pub agent_project_id: String,
    pub session_kind: SessionKind,
    pub logical_profile_key: Option<LogicalProfileKey>,
}

#[cfg(any(test, feature = "test-observer"))]
mod test_observer {
    use std::sync::{Mutex, OnceLock};

    use super::{IdentityResolutionObservation, LogicalProfileKey, RouteIdentity};

    static OBSERVATIONS: OnceLock<Mutex<Vec<IdentityResolutionObservation>>> = OnceLock::new();

    pub(super) fn record(identity: &RouteIdentity, logical_profile_key: Option<LogicalProfileKey>) {
        let observations = OBSERVATIONS.get_or_init(|| Mutex::new(Vec::new()));
        if let Ok(mut observations) = observations.lock() {
            observations.push(IdentityResolutionObservation {
                conversation_key: identity.conversation_key.clone(),
                agent_project_id: identity.agent_project_id.clone(),
                session_kind: identity.session_kind,
                logical_profile_key,
            });
        }
    }

    pub(super) fn take() -> Vec<IdentityResolutionObservation> {
        let observations = OBSERVATIONS.get_or_init(|| Mutex::new(Vec::new()));
        observations
            .lock()
            .map(|mut observations| std::mem::take(&mut *observations))
            .unwrap_or_default()
    }
}

#[cfg(any(test, feature = "test-observer"))]
fn record_test_observation(
    identity: &RouteIdentity,
    logical_profile_key: Option<LogicalProfileKey>,
) {
    test_observer::record(identity, logical_profile_key);
}

/// Drain observations produced by the test-only identity-resolution observer.
#[cfg(any(test, feature = "test-observer"))]
pub fn take_test_observations() -> Vec<IdentityResolutionObservation> {
    test_observer::take()
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

    fn facts(project: &str, kind: &str) -> Value {
        serde_json::json!({
            "agentProjectId": project,
            "sessionKind": kind,
            "effectiveCapabilityScope": ["browser.status"],
        })
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
    fn profile_disposition_matches_session_kind() {
        assert_eq!(
            ProfileDisposition::for_session_kind(SessionKind::Primary),
            ProfileDisposition::Durable
        );
        assert_eq!(
            ProfileDisposition::for_session_kind(SessionKind::Subagent),
            ProfileDisposition::Disposable
        );
        assert_eq!(
            ProfileDisposition::for_session_kind(SessionKind::Ephemeral),
            ProfileDisposition::None
        );
    }

    #[test]
    fn primary_resolves_default_durable_profile() {
        let identity = bind_identity("/tmp/project", "conversation-1");
        let route = RouteIdentity::from_accepted_bind(
            &identity,
            &Some(Principal::Direct),
            Some(&facts("pj-project", "primary")),
        );
        assert_eq!(
            route.resolve_profile(),
            ProfileResolution {
                profile_disposition: ProfileDisposition::Durable,
                profile_name: Some("default".to_string()),
                logical_profile_key: Some(("pj-project".to_string(), "default".to_string())),
            }
        );
    }

    #[test]
    fn subagent_resolves_conversation_scoped_disposable_profile() {
        let identity = bind_identity("/tmp/project", "conversation-1");
        let route = RouteIdentity::from_accepted_bind(
            &identity,
            &Some(Principal::Direct),
            Some(&facts("pj-project", "subagent")),
        );
        assert_eq!(
            route.resolve_profile(),
            ProfileResolution {
                profile_disposition: ProfileDisposition::Disposable,
                profile_name: Some("default".to_string()),
                logical_profile_key: Some(("pj-project".to_string(), "conversation-1".to_string())),
            }
        );
    }

    #[test]
    fn ephemeral_resolves_without_profile_name_or_key() {
        let identity = bind_identity("/tmp/project", "conversation-1");
        let route = RouteIdentity::from_accepted_bind(
            &identity,
            &Some(Principal::Direct),
            Some(&facts("pj-project", "ephemeral")),
        );
        assert_eq!(
            route.resolve_profile(),
            ProfileResolution {
                profile_disposition: ProfileDisposition::None,
                profile_name: None,
                logical_profile_key: None,
            }
        );
    }

    #[test]
    fn admitted_project_and_conversation_facts_are_not_request_fields() {
        let identity = bind_identity("/tmp/request-body-project", "conversation-1");
        let route = RouteIdentity::from_accepted_bind(
            &identity,
            &Some(Principal::Direct),
            Some(&facts("pj-accepted", "subagent")),
        );
        assert_eq!(route.agent_project_id, "pj-accepted");
        assert_eq!(route.conversation_key, "conversation-1");
    }

    #[test]
    fn explicit_scope_is_enforced_without_request_body_input() {
        let bind = bind_identity("/tmp/project", "conversation-1");
        let accepted = AcceptedBindFacts::from_bind(
            &bind,
            Some(Principal::Direct),
            Some(&serde_json::json!({
                "effective_capability_scope": ["other.capability"]
            })),
        );
        assert!(!accepted.allows_capability("browser.status"));
    }

    #[test]
    fn observer_records_identity_and_logical_key() {
        let identity = bind_identity("/tmp/project", "conversation-observed");
        let route = RouteIdentity::from_accepted_bind(
            &identity,
            &Some(Principal::Direct),
            Some(&facts("pj-observed", "subagent")),
        );
        let _ = route.resolve_profile();
        let observations = take_test_observations();
        assert!(observations.iter().any(|observation| {
            observation.conversation_key == "conversation-observed"
                && observation.agent_project_id == "pj-observed"
                && observation.session_kind == SessionKind::Subagent
                && observation.logical_profile_key
                    == Some((
                        "pj-observed".to_string(),
                        "conversation-observed".to_string(),
                    ))
        }));
    }

    #[test]
    fn legacy_bind_defaults_to_primary() {
        let identity = bind_identity("/tmp/project", "session-0001");
        let route = RouteIdentity::from_bind(&identity, &None);
        assert_eq!(route.session_kind, SessionKind::Primary);
        assert_eq!(route.profile_disposition, ProfileDisposition::Durable);
    }

    #[test]
    fn distinct_projects_and_conversations_have_distinct_keys() {
        let same_conversation_a = bind_identity("/tmp/project-a", "conversation-shared");
        let same_conversation_b = bind_identity("/tmp/project-b", "conversation-shared");
        let project_a = RouteIdentity::from_accepted_bind(
            &same_conversation_a,
            &Some(Principal::Direct),
            Some(&facts("pj-a", "primary")),
        );
        let project_b = RouteIdentity::from_accepted_bind(
            &same_conversation_b,
            &Some(Principal::Direct),
            Some(&facts("pj-b", "primary")),
        );
        assert_ne!(
            project_a.resolve_profile().logical_profile_key,
            project_b.resolve_profile().logical_profile_key,
            "different projects must not share a durable profile key"
        );

        let same_project_a = bind_identity("/tmp/project", "conversation-a");
        let same_project_b = bind_identity("/tmp/project", "conversation-b");
        let conversation_a = RouteIdentity::from_accepted_bind(
            &same_project_a,
            &Some(Principal::Direct),
            Some(&facts("pj-shared", "subagent")),
        );
        let conversation_b = RouteIdentity::from_accepted_bind(
            &same_project_b,
            &Some(Principal::Direct),
            Some(&facts("pj-shared", "subagent")),
        );
        assert_ne!(
            conversation_a.resolve_profile().logical_profile_key,
            conversation_b.resolve_profile().logical_profile_key,
            "different subagent conversations must not share a disposable key"
        );
    }
}
