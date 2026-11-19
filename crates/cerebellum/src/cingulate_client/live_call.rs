//! Proof that cerebellum holds a live inbound call from a head or worker session.
//!
//! Core lists cerebellum as a carrier of head and worker session scopes so that it
//! can raise cards for their calls, and for nothing else. Cingulate resolves a
//! worker's stamped parent to the head agent; the request body names neither.
//! The route to Cingulate is opened only while such a call is held: a
//! [`LiveCall`] is made from the call's own in-flight guard and the route it
//! arrived on, and `ConsentDesk::session` re-checks it immediately before
//! every open. Once the call has returned (its guard dropped) or its route has
//! unbound, the proof no longer holds and no route is opened.

use std::sync::{Arc, Weak};

use cerebellum_core::dispatch::InFlightGuard;
use subc_protocol::scope::{ScopeKind, ScopeSelector, ScopeStamp};

use crate::computer_grants::RouteLiveness;

/// Whether the inbound call a [`LiveCall`] was made for is still held.
pub trait CallHold: Send + Sync {
    fn held(&self) -> bool;
}

/// The production hold requires a retained accounting guard, a bound route,
/// and an inbound reply that has not been finalized. Cleanup can retain the
/// accounting guard after replying, so its reference count alone is not authority.
struct InboundCallHold {
    guard: Weak<InFlightGuard>,
    route: Arc<dyn RouteLiveness>,
    terminal: Option<Weak<crate::terminal_arbiter::TerminalArbiter>>,
}

impl CallHold for InboundCallHold {
    fn held(&self) -> bool {
        self.guard.strong_count() > 0
            && self.route.route_open()
            && self.terminal.as_ref().is_none_or(|terminal| {
                terminal
                    .upgrade()
                    .is_some_and(|terminal| terminal.consent_call_held())
            })
    }
}

/// The session a card belongs to: the scope's owner, ref and epoch. Cingulate
/// scopes ownership of cards the same way, so an answer read under one
/// session is never applied for another.
#[derive(Debug, Clone, Eq, serde::Serialize, serde::Deserialize)]
pub struct SessionKey {
    pub owner: String,
    pub scope_ref: String,
    pub scope_epoch: u64,
}

impl SessionKey {
    fn projection(&self) -> (String, &str, u64) {
        let owner = serde_json::from_str::<subc_protocol::Principal>(&self.owner)
            .ok()
            .and_then(|owner| {
                let canonical = cerebellum_core::principal::read_legacy_scope_owner(&owner);
                (canonical != owner || cerebellum_core::principal::is_prefrontal(&owner))
                    .then(|| serde_json::to_string(&canonical).ok())
                    .flatten()
            })
            .unwrap_or_else(|| self.owner.clone());
        (owner, &self.scope_ref, self.scope_epoch)
    }

    pub(super) fn precedes(&self, owner: &str, scope_ref: &str, epoch: u64) -> bool {
        self.scope_epoch < epoch
            && self
                == &Self {
                    owner: owner.into(),
                    scope_ref: scope_ref.into(),
                    scope_epoch: self.scope_epoch,
                }
    }
}

impl PartialEq for SessionKey {
    fn eq(&self, other: &Self) -> bool {
        self.projection() == other.projection()
    }
}

impl std::hash::Hash for SessionKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.projection().hash(state);
    }
}

impl PartialOrd for SessionKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SessionKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.projection().cmp(&other.projection())
    }
}

#[cfg(test)]
mod rename_tests {
    use super::*;
    use std::hash::{Hash, Hasher};

    #[test]
    fn prefrontal_rename_consent_session_preserves_bytes_and_keys() {
        for (before, after) in [
            ("prefrontal-core", "prefrontal"),
            ("prefrontal", "prefrontal-core"),
        ] {
            let make = |name: &str, scope_ref: &str, scope_epoch| SessionKey {
                owner: serde_json::to_string(&subc_protocol::Principal::Reserved {
                    module_id: name.into(),
                })
                .unwrap(),
                scope_ref: scope_ref.into(),
                scope_epoch,
            };
            let old = make(before, "head", 7);
            let new = make(after, "head", 7);
            let bytes = serde_json::to_vec(&old).unwrap();
            let loaded: SessionKey = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(serde_json::to_vec(&loaded).unwrap(), bytes);
            assert_eq!(loaded.owner, old.owner);
            assert_eq!(loaded, new);
            assert_eq!(loaded.cmp(&new), std::cmp::Ordering::Equal);
            let hash = |key: &SessionKey| {
                let mut state = std::collections::hash_map::DefaultHasher::new();
                key.hash(&mut state);
                state.finish()
            };
            assert_eq!(hash(&loaded), hash(&new));
            assert_ne!(loaded, make(after, "other", 7));
            assert_ne!(loaded, make(after, "head", 8));
            assert_ne!(loaded, make("aft", "head", 7));
            let aft = make("aft", "head", 7);
            let mut differently_encoded_aft = aft.clone();
            differently_encoded_aft.owner.insert(0, ' ');
            assert_ne!(aft, differently_encoded_aft);
            let entries = std::collections::BTreeMap::from([(loaded, "card")]);
            assert_eq!(entries.get(&new), Some(&"card"));
        }
    }
}

/// A held inbound call under a head or worker session scope.
pub struct LiveCall {
    scope: ScopeSelector,
    session: SessionKey,
    agent_id: Option<String>,
    hold: Arc<dyn CallHold>,
}

impl std::fmt::Debug for LiveCall {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LiveCall")
            .field("session", &self.session)
            .field("agent_id", &self.agent_id)
            .finish_non_exhaustive()
    }
}

/// Why no [`LiveCall`] could be made, so no card can be raised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotLive {
    /// The call arrived on a route with no session scope: no agent session
    /// lists cerebellum as its carrier.
    Unscoped,
    /// The scope names no agent and is not a worker with a parent, or names a flow.
    /// Cingulate needs a head agent to ask, directly or through a worker's parent.
    NoAgent,
    /// The call is not held any more: its reply was sent or its route unbound.
    CallEnded,
}

impl LiveCall {
    /// The proof for the call currently being served: its scope stamp, its
    /// in-flight guard and the route it arrived on.
    pub fn from_inbound(
        stamp: Option<&ScopeStamp>,
        guard: &Arc<InFlightGuard>,
        route: Arc<dyn RouteLiveness>,
    ) -> Result<Self, NotLive> {
        let hold = Arc::new(InboundCallHold {
            guard: Arc::downgrade(guard),
            terminal: crate::terminal_arbiter::TerminalArbiter::current()
                .as_ref()
                .map(Arc::downgrade),
            route,
        });
        Self::new(stamp, hold)
    }

    pub(crate) fn new(
        stamp: Option<&ScopeStamp>,
        hold: Arc<dyn CallHold>,
    ) -> Result<Self, NotLive> {
        let stamp = stamp.ok_or(NotLive::Unscoped)?;
        let agent_id = stamp
            .attributes
            .agent_id
            .clone()
            .filter(|agent| !agent.trim().is_empty());
        if stamp.attributes.flow_id.is_some()
            || (agent_id.is_none() && (stamp.kind != ScopeKind::Worker || stamp.parent.is_none()))
        {
            return Err(NotLive::NoAgent);
        }
        if !hold.held() {
            return Err(NotLive::CallEnded);
        }
        let owner = serde_json::to_string(&stamp.owner).unwrap_or_default();
        Ok(Self {
            scope: ScopeSelector::new(
                stamp.owner.clone(),
                stamp.scope_ref.clone(),
                Some(stamp.scope_epoch),
            ),
            session: SessionKey {
                owner,
                scope_ref: stamp.scope_ref.clone(),
                scope_epoch: stamp.scope_epoch,
            },
            agent_id,
            hold,
        })
    }

    /// Whether the call is still held right now.
    pub fn is_held(&self) -> bool {
        self.hold.held()
    }

    /// The scope the route to Cingulate asks to be admitted under.
    pub fn scope(&self) -> &ScopeSelector {
        &self.scope
    }

    pub fn session(&self) -> &SessionKey {
        &self.session
    }

    pub fn agent_id(&self) -> Option<&str> {
        self.agent_id.as_deref()
    }

    /// Worker stamps name a parent rather than an agent. Inbound callers may
    /// supply the head identity only after daemon-backed worker resolution.
    pub(crate) fn with_authorizing_agent(mut self, agent: Option<String>) -> Self {
        if self.agent_id.is_none() {
            self.agent_id = agent;
        }
        self
    }
}
