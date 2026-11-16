//! Head claims outlive individual tool routes. The bridge still speaks Route,
//! so one original route is retained as an opaque alias for each stamped session.

use super::*;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct SessionKey {
    owner: String,
    scope_ref: String,
}

impl SessionKey {
    fn new(scope: &subc_protocol::scope::ScopeStamp) -> Self {
        Self {
            owner: serde_json::to_string(&scope.owner).expect("principal serializes"),
            scope_ref: scope.scope_ref.clone(),
        }
    }
}

struct SessionClaim {
    alias: Route,
    last_call: std::time::Instant,
}

#[derive(Default)]
pub(super) struct SessionClaims {
    owners: BTreeMap<SessionKey, SessionClaim>,
    #[cfg(test)]
    clock: Option<std::time::Instant>,
}

impl SessionClaims {
    fn now(&self) -> std::time::Instant {
        #[cfg(test)]
        if let Some(now) = self.clock {
            return now;
        }
        std::time::Instant::now()
    }
}

impl UserBrowser {
    pub(crate) fn session_route(
        &self,
        scope: &subc_protocol::scope::ScopeStamp,
        initial: Route,
    ) -> Route {
        let mut sessions = self.sessions.lock().unwrap();
        let now = sessions.now();
        let session = sessions
            .owners
            .entry(SessionKey::new(scope))
            .or_insert(SessionClaim {
                alias: initial,
                last_call: now,
            });
        session.last_call = now;
        session.alias
    }

    pub(crate) fn retains_route(&self, route: Route) -> bool {
        self.sessions
            .lock()
            .unwrap()
            .owners
            .values()
            .any(|session| session.alias == route)
    }

    pub(crate) fn end_session(&self, key: &crate::scope_watch::ScopeKey) -> Option<Route> {
        self.sessions
            .lock()
            .unwrap()
            .owners
            .remove(&SessionKey {
                owner: serde_json::to_string(&key.owner).expect("principal serializes"),
                scope_ref: key.scope_ref.clone(),
            })
            .map(|session| session.alias)
    }

    pub(crate) fn has_session(&self, key: &crate::scope_watch::ScopeKey) -> bool {
        let sessions = self.sessions.lock().unwrap();
        let Some(session) = sessions.owners.get(&SessionKey {
            owner: serde_json::to_string(&key.owner).expect("principal serializes"),
            scope_ref: key.scope_ref.clone(),
        }) else {
            return false;
        };
        self.state()
            .claims
            .values()
            .any(|owner| *owner == session.alias)
    }

    pub(super) fn stale_claim(
        &self,
        tab: &str,
        claimant: Route,
        routes: &crate::RouteBindings,
    ) -> Option<Route> {
        let owner = *self.state().claims.get(tab)?;
        if owner == claimant {
            return None;
        }
        let mut sessions = self.sessions.lock().unwrap();
        let (key, session) = sessions
            .owners
            .iter()
            .find(|(_, session)| session.alias == owner)?;
        if sessions.now().saturating_duration_since(session.last_call)
            < std::time::Duration::from_secs(30 * 60)
            || routes.has_user_browser_session(&key.owner, &key.scope_ref)
        {
            return None;
        }
        let key = key.clone();
        sessions.owners.remove(&key);
        Some(owner)
    }

    #[cfg(test)]
    pub(super) fn set_claim_clock(&self, now: std::time::Instant) {
        self.sessions.lock().unwrap().clock = Some(now);
    }
}
