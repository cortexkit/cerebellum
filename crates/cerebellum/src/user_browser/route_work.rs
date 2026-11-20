//! Which routes still have person-Chrome work in flight, so an ended route's
//! marker lasts exactly as long as work that could publish for it.
//!
//! A call's claims and snapshots are published only from inside its own
//! `serve`, so work that could publish for a route is work whose `serve` has
//! begun and not returned. Ending a route marks it only while such work is in
//! flight; the marker goes when the last of that work ends, so a delayed
//! result is refused for as long as it can arrive and the markers stay
//! bounded by in-flight work rather than growing with every route ever
//! closed. No timer decides when a marker goes.

use super::{Route, UserBrowser};

/// One `serve` call in flight for a route, from its start to its return.
pub(super) struct RouteWork<'a> {
    target: &'a UserBrowser,
    route: Route,
}

impl UserBrowser {
    pub(super) fn begin_work(&self, route: Route) -> RouteWork<'_> {
        *self.state().in_flight.entry(route).or_default() += 1;
        RouteWork {
            target: self,
            route,
        }
    }

    /// Mark `route` ended for the work still in flight for it. With none in
    /// flight, nothing can still publish for it, and no marker is kept.
    pub(super) fn mark_ended(&self, route: Route) {
        let mut state = self.state();
        if state.in_flight.contains_key(&route) {
            state.ended_routes.insert(route);
        }
    }
}

impl Drop for RouteWork<'_> {
    fn drop(&mut self) {
        let mut state = self.target.state();
        match state.in_flight.get_mut(&self.route) {
            Some(count) if *count > 1 => *count -= 1,
            _ => {
                state.in_flight.remove(&self.route);
                state.ended_routes.remove(&self.route);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser_standing_grants::StandingBrowserGrants;
    use std::sync::Arc;

    fn route(channel: u16) -> Route {
        Route { channel, epoch: 1 }
    }

    /// Routes that end with nothing in flight leave no marker, across a
    /// reconnect too; a route that ends with work in flight keeps its marker
    /// until the last of that work ends.
    #[test]
    fn ended_route_markers_are_bounded_by_work_in_flight() {
        let target = UserBrowser::new(Arc::new(StandingBrowserGrants::in_memory()));
        target.synchronize(7);
        for channel in 1..=500 {
            let work = target.begin_work(route(channel));
            drop(work);
            target.end_route(route(channel));
        }
        target.disconnect();
        target.synchronize(8);
        assert!(target.state().ended_routes.is_empty());
        assert!(target.state().in_flight.is_empty());

        let first = target.begin_work(route(900));
        let second = target.begin_work(route(900));
        target.end_route(route(900));
        target.disconnect();
        target.synchronize(9);
        assert!(target.state().ended_routes.contains(&route(900)));
        drop(first);
        assert!(
            target.state().ended_routes.contains(&route(900)),
            "work still in flight could publish"
        );
        drop(second);
        assert!(target.state().ended_routes.is_empty());
        assert!(target.state().in_flight.is_empty());
    }
}
