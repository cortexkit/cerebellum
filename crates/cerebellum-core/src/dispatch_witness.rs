//! Whether one tool request made a plane commit a dispatch.
//!
//! A caller that resends a call, or asks what became of it, needs to know
//! whether the action was ever dispatched: "it ran" and "it never ran" lead
//! to opposite retries. A reply's own words cannot settle that, because every
//! reply code is written by the handler that returns it; only the commit point
//! a plane passes before its first input (the audit journal's dispatch
//! commitment) proves it. So each request carries a witness, and the plane
//! marks it at that commitment.
//!
//! The witness travels inside the identity values every reservation and
//! commit site already receives ([`crate::journal::JournalIdentity`] and
//! [`crate::identity::RouteIdentity`]). A new site that builds one of those has
//! to name a witness, so it cannot silently drop the request's.
//!
//! A module-wide count backs the witness up: commits made under a detached
//! witness, which no request can claim. The tool handler arms a witness for
//! every request, so in a running module that count moves only when a commit
//! site lost the request's witness (an identity rebuilt without it, or read
//! back from disk). A call whose own witness was never marked, while that
//! count moved during the call, cannot prove it committed nothing, so its
//! answer must be "may have run".

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

static UNATTRIBUTED_COMMITS: AtomicU64 = AtomicU64::new(0);

/// How many dispatch commitments this process made under a detached witness.
pub fn unattributed_commit_count() -> u64 {
    UNATTRIBUTED_COMMITS.load(Ordering::SeqCst)
}

/// One request's witness. Clones share it.
///
/// Equality is always true and it is never serialized: it describes the
/// request in flight, not the identity it rides in, so it must not make two
/// otherwise equal identities differ or reach a durable record.
#[derive(Clone, Default)]
pub struct DispatchWitness(Kind);

#[derive(Clone, Default)]
enum Kind {
    #[default]
    Detached,
    OutsideToolCalls,
    Armed(Arc<AtomicBool>),
}

impl DispatchWitness {
    /// A witness a request's handler reads after the call.
    pub fn armed() -> Self {
        Self(Kind::Armed(Arc::new(AtomicBool::new(false))))
    }

    /// A witness nobody reads: for work that no call record is waiting on
    /// (a call without a key, a recovery pass, a test that drives a plane
    /// directly).
    pub fn detached() -> Self {
        Self(Kind::Detached)
    }

    /// A witness for a commitment no tool request's settlement depends on:
    /// one made by work that is itself outside any plane a request's commit
    /// evidence covers (a browser launch recording its own intent). Its
    /// commits are neither attributed nor counted as unattributed, so they do
    /// not make concurrent calls read as "may have run".
    pub fn outside_tool_calls() -> Self {
        Self(Kind::OutsideToolCalls)
    }

    /// Record that a dispatch was committed for this request. Call it at
    /// every commit point, detached or not: a detached witness counts the
    /// commit as one no request can claim.
    pub fn mark_committed(&self) {
        match &self.0 {
            Kind::Armed(flag) => flag.store(true, Ordering::SeqCst),
            Kind::Detached => {
                UNATTRIBUTED_COMMITS.fetch_add(1, Ordering::SeqCst);
            }
            Kind::OutsideToolCalls => {}
        }
    }

    /// Whether a dispatch was committed for this request.
    pub fn committed(&self) -> bool {
        matches!(&self.0, Kind::Armed(flag) if flag.load(Ordering::SeqCst))
    }
}

impl std::fmt::Debug for DispatchWitness {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Kind::Detached => formatter.write_str("DispatchWitness(detached)"),
            Kind::OutsideToolCalls => formatter.write_str("DispatchWitness(outside tool calls)"),
            Kind::Armed(_) => {
                write!(
                    formatter,
                    "DispatchWitness(committed: {})",
                    self.committed()
                )
            }
        }
    }
}

impl PartialEq for DispatchWitness {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for DispatchWitness {}
