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
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct SessionKey {
    pub owner: String,
    pub scope_ref: String,
    pub scope_epoch: u64,
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
            scope: ScopeSelector {
                owner: stamp.owner.clone(),
                scope_ref: stamp.scope_ref.clone(),
                scope_epoch: Some(stamp.scope_epoch),
            },
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
}
