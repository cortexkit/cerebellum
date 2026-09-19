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

/// Proof that a [`GrantKind::Once`] lease was consumed for one dispatch.
///
/// Constructible only by consuming a Once lease through [`ConsentLeases::admit_use`].
/// No `Default`, no `Clone`: a standing [`GrantKind::Until`] grant cannot
/// produce this token, so a durable configuration grant cannot pre-authorize
/// global dispatch until a later review changes that on purpose.
#[derive(Debug, PartialEq, Eq)]
pub struct OnceDispatchToken {
    _private: (),
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
///
/// The two pending outcomes are separate because the caller must act
/// differently: one has to put the question to the user, and the other must not.
/// Collapsing them would make a repeat request re-prompt for something already
/// on screen, which is how joining an ask in flight stops meaning anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opening {
    /// A lease already covers this, with no need to ask.
    AlreadyHeld(Lease),
    /// Nothing covers this and nothing is being asked, so the question is the
    /// caller's to put.
    AskNeeded(PendingAsk),
    /// This is already being asked. The caller waits for that answer rather than
    /// asking again.
    AlreadyAsking(PendingAsk),
}

impl Opening {
    /// The ask this resolves to, if it is not already covered.
    pub fn pending(&self) -> Option<&PendingAsk> {
        match self {
            Self::AlreadyHeld(_) => None,
            Self::AskNeeded(ask) | Self::AlreadyAsking(ask) => Some(ask),
        }
    }
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
    /// The application a targetless request means, per grantee and action kind.
    ///
    /// Some requests carry no target by design: a screenshot names a scope and
    /// nothing else, so that a caller cannot point the plane at a process by
    /// naming it. That leaves the question of WHICH leased application such a
    /// request refers to when several are held, and the frozen request schema
    /// has nowhere to answer it.
    ///
    /// Answered by the most recent opening rather than by a rule about the
    /// machine's state. Choosing the frontmost or the oldest lease would derive
    /// it from something the agent did not say and the user did not decide,
    /// which is the objection that rules out frontmost-application targeting.
    /// The most recent opening is an act the agent performed deliberately.
    ///
    /// Cheap to change and never a second prompt: re-opening an application
    /// still under consent is admitted from the lease that already exists, so
    /// an agent working across two applications pays a round trip to switch and
    /// the user is asked once per application.
    focus: HashMap<(String, ActionKind), String>,
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

    /// Consume a Once lease into a one-shot dispatch token.
    ///
    /// Goes through [`Self::admit_use`]: an Until lease of any duration is
    /// admitted without being spent and still does not yield a token. Only a
    /// consumed Once does. A second call on the same key yields nothing
    /// because the lease was spent.
    pub fn admit_once_dispatch<C: MonotonicClock>(
        &mut self,
        key: &LeaseKey,
        clock: &C,
    ) -> Option<OnceDispatchToken> {
        match self.admit_use(key, clock) {
            Admission::Admitted(lease) if lease.kind == GrantKind::Once => {
                Some(OnceDispatchToken { _private: () })
            }
            _ => None,
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
            self.focus.insert(
                (key.grantee.clone(), key.action_kind),
                key.bundle_identity.clone(),
            );
            return Opening::AlreadyHeld(lease);
        }
        // A request for something already being asked about joins that ask. The
        // alternative forks consent state: two asks over one key can be answered
        // differently, and nothing here could say which answer governs.
        if let Some(pending) = self.pending.get(&key) {
            return Opening::AlreadyAsking(pending.clone());
        }
        let pending = PendingAsk {
            key: key.clone(),
            ask_id: mint_ask_id(),
            asked_at: clock.now(),
        };
        self.pending.insert(key, pending.clone());
        Opening::AskNeeded(pending)
    }

    /// Record the user's answer to a pending ask.
    ///
    /// Returns the lease if one was granted. An ask nobody is waiting for is
    /// reported by `None` with no lease minted, rather than being treated as an
    /// answer to something: an answer to an ask this store does not hold is
    /// either a late reply to one already resolved, or an answer to a question it
    /// never posed, and neither may create authority.
    /// The key an outstanding ask belongs to, if it is still outstanding.
    ///
    /// Exposed so a caller settling an ask can record something ABOUT that
    /// target: the key is the only identity a later request for the same thing
    /// will arrive under, and it is gone once the ask is settled.
    pub fn pending_key(&self, ask_id: &str) -> Option<LeaseKey> {
        self.pending
            .iter()
            .find(|(_, pending)| pending.ask_id == ask_id)
            .map(|(key, _)| key.clone())
    }

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
        granted.map(|kind| {
            // Focus follows the grant, so the application a user has just
            // approved is the one a targetless request means.
            self.focus.insert(
                (key.grantee.clone(), key.action_kind),
                key.bundle_identity.clone(),
            );
            self.grant(key, kind, clock).0
        })
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

    /// Which application a targetless request means, if any is admitted.
    ///
    /// Returns nothing when the focused application's lease no longer admits,
    /// rather than falling back to another one that happens to be held. A
    /// caller that asked about one application must not silently be answered
    /// about a different one.
    pub fn focused<C: MonotonicClock>(
        &mut self,
        grantee: &str,
        action_kind: ActionKind,
        clock: &C,
    ) -> Option<LeaseKey> {
        let bundle_identity = self
            .focus
            .get(&(grantee.to_string(), action_kind))
            .cloned()?;
        let key = LeaseKey {
            grantee: grantee.to_string(),
            bundle_identity,
            action_kind,
        };
        self.admits(&key, clock).is_admitted().then_some(key)
    }

    /// Drop a lease, returning it if one was held.
    pub fn revoke(&mut self, key: &LeaseKey) -> Option<Lease> {
        self.focus.remove(&(key.grantee.clone(), key.action_kind));
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

        let Opening::AskNeeded(first) = leases.open(target.clone(), &clock, || "ask-1".to_string())
        else {
            panic!("an unleased target must need an ask");
        };
        // The second request must report that the question is ALREADY being
        // asked, not that one is needed: a caller told a question is needed puts
        // it, and the user would see the same prompt twice.
        let Opening::AlreadyAsking(second) =
            leases.open(target, &clock, || panic!("a second ask was minted"))
        else {
            panic!("a repeat request must join the ask in flight");
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

        let Opening::AskNeeded(observing) = leases.open(key(ActionKind::Observe), &clock, || {
            "ask-observe".to_string()
        }) else {
            panic!("an unleased target must need an ask");
        };
        let Opening::AskNeeded(composing) = leases.open(key(ActionKind::Compose), &clock, || {
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

    /// A targetless request means the application most recently opened.
    ///
    /// Several leases can be held at once, and a request that carries no target
    /// has to mean one of them. The most recent opening is the agent's own act,
    /// where the frontmost window or the oldest lease would be a property of the
    /// machine that nobody chose.
    #[test]
    fn the_most_recently_opened_application_is_the_focused_one() {
        let mut leases = ConsentLeases::new();
        let clock = FakeClock::new();

        let safari = key(ActionKind::Observe);
        let mail = LeaseKey {
            bundle_identity: "com.apple.Mail".to_string(),
            ..key(ActionKind::Observe)
        };

        leases.grant(safari.clone(), GrantKind::Until(at(10_000)), &clock);
        leases.grant(mail.clone(), GrantKind::Until(at(10_000)), &clock);

        // Granting alone does not focus: opening is what an agent does.
        let _ = leases.open(safari.clone(), &clock, unreachable_ask);
        assert_eq!(
            leases.focused("pj-example", ActionKind::Observe, &clock),
            Some(safari.clone())
        );

        let _ = leases.open(mail.clone(), &clock, unreachable_ask);
        assert_eq!(
            leases.focused("pj-example", ActionKind::Observe, &clock),
            Some(mail)
        );

        // Switching back costs no prompt, because the lease still admits.
        let opening = leases.open(safari.clone(), &clock, unreachable_ask);
        assert!(matches!(opening, Opening::AlreadyHeld(_)));
        assert_eq!(
            leases.focused("pj-example", ActionKind::Observe, &clock),
            Some(safari)
        );
    }

    /// Focus does not survive its lease.
    ///
    /// Once the focused application's lease stops admitting, a targetless
    /// request has no answer rather than quietly meaning some other application
    /// that happens to still be leased.
    #[test]
    fn focus_does_not_outlive_the_lease_it_names() {
        let mut leases = ConsentLeases::new();
        let mut clock = FakeClock::new();

        let safari = key(ActionKind::Observe);
        let mail = LeaseKey {
            bundle_identity: "com.apple.Mail".to_string(),
            ..key(ActionKind::Observe)
        };
        leases.grant(mail, GrantKind::Until(at(60_000)), &clock);
        leases.grant(safari.clone(), GrantKind::Until(at(10_000)), &clock);
        let _ = leases.open(safari, &clock, unreachable_ask);

        clock.advance(Duration::from_millis(10_000));
        assert_eq!(
            leases.focused("pj-example", ActionKind::Observe, &clock),
            None,
            "an expired focus fell back to another application"
        );
    }

    /// Looking and touching are focused separately.
    #[test]
    fn each_action_kind_has_its_own_focus() {
        let mut leases = ConsentLeases::new();
        let clock = FakeClock::new();

        let observing = key(ActionKind::Observe);
        let composing = LeaseKey {
            bundle_identity: "com.apple.Mail".to_string(),
            ..key(ActionKind::Compose)
        };
        leases.grant(observing.clone(), GrantKind::Until(at(10_000)), &clock);
        leases.grant(composing.clone(), GrantKind::Until(at(10_000)), &clock);
        let _ = leases.open(observing.clone(), &clock, unreachable_ask);
        let _ = leases.open(composing.clone(), &clock, unreachable_ask);

        assert_eq!(
            leases.focused("pj-example", ActionKind::Observe, &clock),
            Some(observing)
        );
        assert_eq!(
            leases.focused("pj-example", ActionKind::Compose, &clock),
            Some(composing)
        );
    }

    fn unreachable_ask() -> String {
        panic!("a held lease must not ask")
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

    /// A standing Until grant of any duration does not yield a dispatch token.
    /// Only a consumed Once does, and a second consume on the same key yields
    /// nothing because the lease was spent.
    #[test]
    fn only_a_consumed_once_lease_yields_a_dispatch_token() {
        let mut leases = ConsentLeases::new();
        let clock = FakeClock::new();
        let until_key = key(ActionKind::Compose);
        let once_key = LeaseKey {
            bundle_identity: "com.apple.Mail".to_string(),
            ..key(ActionKind::Compose)
        };

        leases.grant(until_key.clone(), GrantKind::Until(at(10_000)), &clock);
        assert!(
            leases.admit_once_dispatch(&until_key, &clock).is_none(),
            "an Until lease yielded a one-shot dispatch token"
        );
        assert!(
            leases.admits(&until_key, &clock).is_admitted(),
            "asking for a token spent the Until lease"
        );

        leases.grant(once_key.clone(), GrantKind::Once, &clock);
        assert!(
            leases.admit_once_dispatch(&once_key, &clock).is_some(),
            "a consumed Once lease did not yield a token"
        );
        assert!(
            leases.admit_once_dispatch(&once_key, &clock).is_none(),
            "a second admit_use on a spent Once lease yielded another token"
        );
        assert_eq!(
            leases.admit_use(&once_key, &clock),
            Admission::NeedsConsent(NeedsConsent::NoLeaseHeld)
        );
    }
}
