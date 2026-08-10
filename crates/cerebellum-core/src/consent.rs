//! Consent leases: what a user's answer bought, and for how long.
//!
//! A prompt asks the user whether an agent may reach one application. This holds
//! the answer. The two halves are deliberately separate: the ASK is the consent
//! record, owned by the executive that renders it to every surface, and the LEASE
//! is the grant, owned here. So the ask stores which option a user chose and this
//! stores what that choice means.
//!
//! Plane-agnostic on purpose. A browser reaching one of the user's own browsers
//! and a desktop action reaching one application ask the same question, and
//! answering it twice in two places is how the two answers drift.
//!
//! WHAT THIS DELIBERATELY DOES NOT HOLD:
//!
//! * Denials. A user declining is recorded by the ask, not here, and how long a
//!   decline suppresses re-asking is an open question — re-asking immediately
//!   would let an agent's retry loop spam a prompt, and inventing a cooldown
//!   here would settle a consent question in a data structure.
//! * Anything durable. Leases live in memory and die with the process, because
//!   after a restart the grant was made to a process that no longer exists.

use std::collections::HashMap;

use crate::clock::{MonoInstant, MonotonicClock};

/// What a granted lease permits, in the two shapes a prompt can offer.
///
/// There is no indefinite variant, and the omission is the point: an
/// open-ended grant to reach an application is one nobody could later say they
/// issued. Durable permission is a configuration act, deliberately taken,
/// rather than something reachable by answering a prompt while distracted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantKind {
    /// One use, consumed by the first action it admits.
    Once,
    /// Every use until this instant.
    ///
    /// An instant from the granting clock rather than a duration, so expiry is a
    /// COMPARISON rather than a subtraction. A subtraction has to decide what a
    /// negative result means, and the reading that saturates to zero would make
    /// a misbehaving clock report every lease as unexpired.
    Until(MonoInstant),
}

/// Which kind of action a lease admits.
///
/// Looking and touching are separate grants: approving a screenshot of a browser
/// must not approve clicking inside it. The seam is what the action DOES rather
/// than which plane serves it, so a capability declares its kind and the gate
/// follows, and anything undeclared takes the strict side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ActionKind {
    /// Reads state and leaves the machine as it found it.
    Observe,
    /// Changes where the user's next keystroke goes.
    Compose,
    /// Changes state that outlives the session.
    MutateDurable,
}

/// Who holds a grant, and what it is over.
///
/// The target is named by bundle identity rather than by process id: a caller
/// supplying a pid could name a process it had no legitimate way to discover,
/// which is a capability leak wearing an ergonomic disguise. Resolving a bundle
/// identity to a live process — and refusing when two instances are running —
/// happens before a lease is ever consulted.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LeaseKey {
    /// The durable agent identity the user granted to.
    ///
    /// Not the conversation: a conversation is one thread of a long-lived agent,
    /// and a grant made to an agent should not evaporate because it started a
    /// new thread of its own work.
    pub grantee: String,
    pub bundle_identity: String,
    pub action_kind: ActionKind,
}

/// A granted lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub key: LeaseKey,
    pub kind: GrantKind,
    pub granted_at: MonoInstant,
    /// Distinguishes this grant from any earlier one over the same key, so a
    /// caller holding a stale reference cannot present it as current.
    pub generation: u64,
}

/// Why an action is not admitted without asking again.
///
/// Both variants lead to the same place — a prompt — which is the point: an
/// expired lease is NOT-YET-GRANTED-AGAIN rather than a refusal, so it takes the
/// same path as a first request instead of surfacing an error an agent could
/// learn to route around.
///
/// They report what this store KNOWS, which is narrower than the history a
/// reader might want. There is deliberately no "was granted and used up"
/// variant: consuming a single-use lease removes it, after which nothing here
/// can tell that case from one never granted at all. Naming it would be a claim
/// about history this store does not keep. The fact is available at the moment it
/// happens — `admit_use` hands back the lease it spent — so a caller that wants
/// it in the journal records it there rather than rediscovering it later from a
/// structure that dropped it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeedsConsent {
    /// This store holds no lease for the key.
    ///
    /// Named for the store's state rather than for the user's history: it covers
    /// a key never granted and one whose single use is spent, and this cannot
    /// distinguish them.
    NoLeaseHeld,
    /// A lease covered it and its time ran out.
    ///
    /// Distinct from holding none because the two are different facts about the
    /// same conversation, and this one is worth journaling: a grant existed and
    /// the user's answer ran out.
    Expired,
}

/// The answer to "may this agent do this to this application, right now".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// Admitted under this lease.
    Admitted(Lease),
    /// Not admitted, and the remedy is to ask rather than to fail.
    NeedsConsent(NeedsConsent),
}

impl Admission {
    /// Whether the action may proceed.
    pub const fn is_admitted(&self) -> bool {
        matches!(self, Self::Admitted(_))
    }
}

/// A consent request that has been put to the user and not yet answered.
///
/// Held so a second request for the same thing joins the ask already in flight
/// rather than minting a sibling. Two asks over one key would let a user answer
/// one and leave the other pending, after which the module's view of consent
/// depends on which ask it happens to consult.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAsk {
    pub key: LeaseKey,
    /// The identity the user's answer will arrive against.
    pub ask_id: String,
    pub asked_at: MonoInstant,
}

/// What a request to reach an application resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opening {
    /// A lease already covers this, with no need to ask.
    AlreadyHeld(Lease),
    /// The user is being asked. Carries the ask so a caller can follow it, and
    /// so a repeat request joins this one instead of starting another.
    Pending(PendingAsk),
}

/// The leases a module currently holds.
///
/// Expiry is evaluated when a lease is USED rather than by a timer, so the
/// admission check and any identity re-verification alongside it read the same
/// state at the same instant. A timer that revoked independently would be a
/// second source of truth that can disagree with the first.
#[derive(Debug, Default)]
pub struct ConsentLeases {
    leases: HashMap<LeaseKey, Lease>,
    /// Asks put to the user and not yet answered.
    ///
    /// Keyed by the FULL lease key rather than by grantee and application alone.
    /// Looking and touching are separate grants, so a narrower key would hand an
    /// agent asking to act the pending ask for permission to observe -- and an
    /// answer to that ask would then read as consent for something the user was
    /// never shown.
    pending: HashMap<LeaseKey, PendingAsk>,
    next_generation: u64,
}

impl ConsentLeases {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a user's answer as a lease, replacing any earlier one for the key.
    ///
    /// Replacement is explicit rather than incidental: the previous lease is
    /// removed and returned, so a caller can journal that it ended rather than
    /// leaving two grants over one key whose expiries disagree about which
    /// applies.
    pub fn grant<C: MonotonicClock>(
        &mut self,
        key: LeaseKey,
        kind: GrantKind,
        clock: &C,
    ) -> (Lease, Option<Lease>) {
        let superseded = self.leases.remove(&key);
        self.next_generation += 1;
        let lease = Lease {
            key: key.clone(),
            kind,
            granted_at: clock.now(),
            generation: self.next_generation,
        };
        self.leases.insert(key, lease.clone());
        (lease, superseded)
    }

    /// Whether a key is admitted now, without consuming a single-use lease.
    ///
    /// An expired lease is dropped as it is found, so a lease that has run out
    /// does not sit in the map claiming to be a grant.
    pub fn admits<C: MonotonicClock>(&mut self, key: &LeaseKey, clock: &C) -> Admission {
        let Some(lease) = self.leases.get(key) else {
            return Admission::NeedsConsent(NeedsConsent::NoLeaseHeld);
        };
        match lease.kind {
            GrantKind::Once => Admission::Admitted(lease.clone()),
            GrantKind::Until(expiry) => {
                // A comparison rather than an age: `MonoInstant` is only
                // comparable within one clock, so this cannot silently compare
                // readings from two.
                if clock.now() < expiry {
                    Admission::Admitted(lease.clone())
                } else {
                    self.leases.remove(key);
                    Admission::NeedsConsent(NeedsConsent::Expired)
                }
            }
        }
    }

    /// Admit an action and consume whatever the lease spends.
    ///
    /// Separate from [`Self::admits`] because asking whether something is
    /// permitted and spending the permission are different acts, and a caller
    /// that checks twice before acting should not burn a single-use grant on the
    /// check. A caller that acts must call this one.
    pub fn admit_use<C: MonotonicClock>(&mut self, key: &LeaseKey, clock: &C) -> Admission {
        match self.admits(key, clock) {
            Admission::Admitted(lease) => {
                if lease.kind == GrantKind::Once {
                    self.leases.remove(key);
                }
                Admission::Admitted(lease)
            }
            needs => needs,
        }
    }

    /// Resolve a request to reach an application, asking only if needed.
    ///
    /// `mint_ask_id` is called only when an ask is actually required, so a caller
    /// that already holds a lease neither creates an ask nor consumes an
    /// identifier for one.
    pub fn open<C: MonotonicClock, F: FnOnce() -> String>(
        &mut self,
        key: LeaseKey,
        clock: &C,
        mint_ask_id: F,
    ) -> Opening {
        if let Admission::Admitted(lease) = self.admits(&key, clock) {
            return Opening::AlreadyHeld(lease);
        }
        // A request for something already being asked about joins that ask. The
        // alternative forks consent state: two asks over one key can be answered
        // differently, and nothing here could say which answer governs.
        if let Some(pending) = self.pending.get(&key) {
            return Opening::Pending(pending.clone());
        }
        let pending = PendingAsk {
            key: key.clone(),
            ask_id: mint_ask_id(),
            asked_at: clock.now(),
        };
        self.pending.insert(key, pending.clone());
        Opening::Pending(pending)
    }

    /// Record the user's answer to a pending ask.
    ///
    /// Returns the lease if one was granted. An ask nobody is waiting for is
    /// reported by `None` with no lease minted, rather than being treated as an
    /// answer to something: an answer to an ask this store does not hold is
    /// either a late reply to one already resolved, or an answer to a question it
    /// never posed, and neither may create authority.
    pub fn settle<C: MonotonicClock>(
        &mut self,
        ask_id: &str,
        granted: Option<GrantKind>,
        clock: &C,
    ) -> Option<Lease> {
        let key = self
            .pending
            .iter()
            .find(|(_, pending)| pending.ask_id == ask_id)
            .map(|(key, _)| key.clone())?;
        self.pending.remove(&key);
        granted.map(|kind| self.grant(key, kind, clock).0)
    }

    /// How long until a lease stops admitting, from the caller's point of view.
    ///
    /// A duration rather than the expiry instant, because an instant is
    /// comparable only to others from the same clock and a caller reading this
    /// elsewhere has no access to that clock. Handing one out would look
    /// sufficient and mean nothing: nothing at the far end fails, the caller
    /// compares it against its own clock, and the answer is plausible and wrong.
    ///
    /// IT IS AN UPPER BOUND, NOT A FENCE. The value is already stale when it
    /// arrives — by however long it took to get there, plus whatever the caller
    /// does before acting — so it is worth planning against and not worth
    /// relying on. The expiry comparison made here at the moment of use stays
    /// the authority, and a caller acting on a nearly-expired lease should
    /// expect the refusal rather than try to beat it.
    ///
    /// `None` for a single-use grant, which is not bounded by time at all.
    pub fn remaining<C: MonotonicClock>(lease: &Lease, clock: &C) -> Option<core::time::Duration> {
        match lease.kind {
            GrantKind::Once => None,
            GrantKind::Until(expiry) => Some(core::time::Duration::from_nanos(
                expiry.as_nanos().saturating_sub(clock.now().as_nanos()),
            )),
        }
    }

    /// Whether an ask is outstanding for a key.
    pub fn is_pending(&self, key: &LeaseKey) -> bool {
        self.pending.contains_key(key)
    }

    /// Drop a lease, returning it if one was held.
    pub fn revoke(&mut self, key: &LeaseKey) -> Option<Lease> {
        self.leases.remove(key)
    }

    /// How many leases are held, expired ones included until they are next used.
    pub fn len(&self) -> usize {
        self.leases.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leases.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FakeClock;
    use std::time::Duration;

    fn key(action_kind: ActionKind) -> LeaseKey {
        LeaseKey {
            grantee: "pj-example".to_string(),
            bundle_identity: "com.apple.Safari".to_string(),
            action_kind,
        }
    }

    fn at(millis: u64) -> MonoInstant {
        MonoInstant::from_duration(Duration::from_millis(millis))
    }

    /// A key nobody granted needs consent, and says it was never granted.
    #[test]
    fn an_ungranted_key_needs_consent() {
        let mut leases = ConsentLeases::new();
        let clock = FakeClock::new();
        assert_eq!(
            leases.admits(&key(ActionKind::Observe), &clock),
            Admission::NeedsConsent(NeedsConsent::NoLeaseHeld)
        );
    }

    /// A time-boxed lease admits before its instant and needs consent after.
    ///
    /// The accepting half is asserted alongside the refusing half, because a
    /// store that admitted nothing would satisfy every refusal test here.
    #[test]
    fn a_time_boxed_lease_admits_until_its_instant() {
        let mut leases = ConsentLeases::new();
        let mut clock = FakeClock::new();
        let target = key(ActionKind::Observe);

        leases.grant(target.clone(), GrantKind::Until(at(10_000)), &clock);
        assert!(leases.admits(&target, &clock).is_admitted());

        clock.advance(Duration::from_millis(9_999));
        assert!(leases.admits(&target, &clock).is_admitted());

        clock.advance(Duration::from_millis(1));
        assert_eq!(
            leases.admits(&target, &clock),
            Admission::NeedsConsent(NeedsConsent::Expired)
        );
    }

    /// An expired lease stops being held rather than lingering as a grant.
    #[test]
    fn an_expired_lease_is_dropped_when_found() {
        let mut leases = ConsentLeases::new();
        let mut clock = FakeClock::new();
        let target = key(ActionKind::Observe);

        leases.grant(target.clone(), GrantKind::Until(at(1_000)), &clock);
        assert_eq!(leases.len(), 1);

        clock.advance(Duration::from_millis(1_000));
        let _ = leases.admits(&target, &clock);
        assert!(leases.is_empty(), "an expired lease was retained");
    }

    /// Checking does not spend a single-use lease; acting does.
    ///
    /// The distinction is what stops a caller that verifies twice before acting
    /// from burning the grant on a check. Asserted in both directions, since a
    /// store that consumed on neither call would pass the first half alone.
    #[test]
    fn only_using_a_single_use_lease_consumes_it() {
        let mut leases = ConsentLeases::new();
        let clock = FakeClock::new();
        let target = key(ActionKind::Compose);

        leases.grant(target.clone(), GrantKind::Once, &clock);
        assert!(leases.admits(&target, &clock).is_admitted());
        assert!(
            leases.admits(&target, &clock).is_admitted(),
            "checking spent the grant"
        );

        assert!(leases.admit_use(&target, &clock).is_admitted());
        assert_eq!(
            leases.admit_use(&target, &clock),
            Admission::NeedsConsent(NeedsConsent::NoLeaseHeld),
            "a single-use grant admitted a second action"
        );
    }

    /// Looking and touching are separate grants over the same application.
    #[test]
    fn a_grant_to_observe_does_not_admit_composing() {
        let mut leases = ConsentLeases::new();
        let clock = FakeClock::new();

        leases.grant(
            key(ActionKind::Observe),
            GrantKind::Until(at(10_000)),
            &clock,
        );

        assert!(leases
            .admits(&key(ActionKind::Observe), &clock)
            .is_admitted());
        assert_eq!(
            leases.admits(&key(ActionKind::Compose), &clock),
            Admission::NeedsConsent(NeedsConsent::NoLeaseHeld),
            "a grant to look admitted an action that touches"
        );
        assert_eq!(
            leases.admits(&key(ActionKind::MutateDurable), &clock),
            Admission::NeedsConsent(NeedsConsent::NoLeaseHeld)
        );
    }

    /// A grant to one agent admits nothing for another.
    #[test]
    fn a_grant_to_one_agent_admits_nothing_for_another() {
        let mut leases = ConsentLeases::new();
        let clock = FakeClock::new();

        leases.grant(
            key(ActionKind::Observe),
            GrantKind::Until(at(10_000)),
            &clock,
        );

        let other = LeaseKey {
            grantee: "pj-somebody-else".to_string(),
            ..key(ActionKind::Observe)
        };
        assert_eq!(
            leases.admits(&other, &clock),
            Admission::NeedsConsent(NeedsConsent::NoLeaseHeld)
        );
    }

    /// A grant over one application admits nothing over another.
    #[test]
    fn a_grant_over_one_application_admits_nothing_over_another() {
        let mut leases = ConsentLeases::new();
        let clock = FakeClock::new();

        leases.grant(
            key(ActionKind::Observe),
            GrantKind::Until(at(10_000)),
            &clock,
        );

        let other = LeaseKey {
            bundle_identity: "com.apple.Mail".to_string(),
            ..key(ActionKind::Observe)
        };
        assert_eq!(
            leases.admits(&other, &clock),
            Admission::NeedsConsent(NeedsConsent::NoLeaseHeld)
        );
    }

    /// A request for something already leased does not ask again.
    ///
    /// The ask-minting closure must not run: a caller holding a lease should not
    /// consume an ask identifier, and running it would mean the store asks for
    /// permission it already has.
    #[test]
    fn opening_something_already_leased_does_not_ask() {
        let mut leases = ConsentLeases::new();
        let clock = FakeClock::new();
        let target = key(ActionKind::Observe);
        leases.grant(target.clone(), GrantKind::Until(at(10_000)), &clock);

        let opening = leases.open(target, &clock, || panic!("asked despite holding a lease"));
        assert!(matches!(opening, Opening::AlreadyHeld(_)));
    }

    /// A second request for the same thing joins the ask already in flight.
    ///
    /// Two asks over one key could be answered differently, after which the
    /// store's view of consent depends on which one it consults.
    #[test]
    fn a_repeat_request_joins_the_ask_in_flight() {
        let mut leases = ConsentLeases::new();
        let clock = FakeClock::new();
        let target = key(ActionKind::Observe);

        let Opening::Pending(first) = leases.open(target.clone(), &clock, || "ask-1".to_string())
        else {
            panic!("an unleased target must ask");
        };
        let Opening::Pending(second) =
            leases.open(target, &clock, || panic!("a second ask was minted"))
        else {
            panic!("a pending target must stay pending");
        };
        assert_eq!(first.ask_id, second.ask_id);
    }

    /// Asking to act does not join a pending ask about observing.
    ///
    /// Looking and touching are separate grants, so keying pending asks by
    /// grantee and application alone would hand an agent asking to compose the
    /// ask for permission to observe -- and the user's answer to THAT question
    /// would then read as consent for something they were never shown.
    #[test]
    fn an_ask_to_observe_is_not_reused_for_composing() {
        let mut leases = ConsentLeases::new();
        let clock = FakeClock::new();

        let Opening::Pending(observing) = leases.open(key(ActionKind::Observe), &clock, || {
            "ask-observe".to_string()
        }) else {
            panic!("an unleased target must ask");
        };
        let Opening::Pending(composing) = leases.open(key(ActionKind::Compose), &clock, || {
            "ask-compose".to_string()
        }) else {
            panic!("a different action kind must ask separately");
        };

        assert_ne!(
            observing.ask_id, composing.ask_id,
            "an ask about looking was reused for an action that touches"
        );
    }

    /// Settling a granted ask mints the lease and clears the ask.
    #[test]
    fn settling_a_granted_ask_mints_its_lease() {
        let mut leases = ConsentLeases::new();
        let clock = FakeClock::new();
        let target = key(ActionKind::Observe);
        let _ = leases.open(target.clone(), &clock, || "ask-1".to_string());

        let lease = leases
            .settle("ask-1", Some(GrantKind::Until(at(10_000))), &clock)
            .expect("a granted ask mints a lease");
        assert_eq!(lease.key, target);
        assert!(!leases.is_pending(&target), "a settled ask stayed pending");
        assert!(leases.admits(&target, &clock).is_admitted());
    }

    /// Settling a declined ask mints nothing and clears the ask.
    ///
    /// The ask must clear either way: leaving it pending after a refusal would
    /// make every later request join an ask the user has already answered.
    #[test]
    fn settling_a_declined_ask_mints_nothing() {
        let mut leases = ConsentLeases::new();
        let clock = FakeClock::new();
        let target = key(ActionKind::Observe);
        let _ = leases.open(target.clone(), &clock, || "ask-1".to_string());

        assert!(leases.settle("ask-1", None, &clock).is_none());
        assert!(!leases.is_pending(&target), "a declined ask stayed pending");
        assert_eq!(
            leases.admits(&target, &clock),
            Admission::NeedsConsent(NeedsConsent::NoLeaseHeld)
        );
    }

    /// An answer to an ask this store does not hold creates nothing.
    ///
    /// A late reply to an ask already settled, or an answer to a question never
    /// posed. Neither may create authority, and the second is the one that
    /// matters: an answer alone must not be able to mint a lease.
    #[test]
    fn an_answer_to_an_unknown_ask_creates_no_lease() {
        let mut leases = ConsentLeases::new();
        let clock = FakeClock::new();

        assert!(leases
            .settle("never-asked", Some(GrantKind::Until(at(10_000))), &clock)
            .is_none());
        assert!(leases.is_empty(), "an unknown answer minted a lease");
    }

    /// Remaining time is reported as a duration, and runs down.
    ///
    /// A single-use grant has none: it is not bounded by time at all, and
    /// reporting zero would read as expired.
    #[test]
    fn remaining_time_counts_down_and_is_absent_for_single_use() {
        let mut leases = ConsentLeases::new();
        let mut clock = FakeClock::new();
        let target = key(ActionKind::Observe);

        let (timed, _) = leases.grant(target.clone(), GrantKind::Until(at(10_000)), &clock);
        assert_eq!(
            ConsentLeases::remaining(&timed, &clock),
            Some(Duration::from_millis(10_000))
        );

        clock.advance(Duration::from_millis(4_000));
        assert_eq!(
            ConsentLeases::remaining(&timed, &clock),
            Some(Duration::from_millis(6_000))
        );

        let (once, _) = leases.grant(key(ActionKind::Compose), GrantKind::Once, &clock);
        assert_eq!(ConsentLeases::remaining(&once, &clock), None);
    }

    /// Re-granting hands back the lease it replaced, and only one remains.
    ///
    /// The superseded lease is returned so its end can be recorded. Two live
    /// leases over one key would disagree about which expiry applies, and
    /// whichever a reader consulted first would look authoritative.
    #[test]
    fn regranting_supersedes_rather_than_accumulates() {
        let mut leases = ConsentLeases::new();
        let mut clock = FakeClock::new();
        let target = key(ActionKind::Observe);

        let (first, none) = leases.grant(target.clone(), GrantKind::Until(at(1_000)), &clock);
        assert!(none.is_none());

        let (second, superseded) =
            leases.grant(target.clone(), GrantKind::Until(at(9_000)), &clock);
        assert_eq!(superseded, Some(first.clone()));
        assert_eq!(leases.len(), 1, "re-granting accumulated a second lease");
        assert_ne!(
            second.generation, first.generation,
            "the replacement is indistinguishable from what it replaced"
        );

        // The new expiry governs: the old one has already passed.
        clock.advance(Duration::from_millis(1_000));
        assert!(leases.admits(&target, &clock).is_admitted());
    }
}
