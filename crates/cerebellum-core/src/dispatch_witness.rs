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

#[cfg(feature = "test-support")]
thread_local! {
    static FIXTURE_WITNESS: std::cell::RefCell<Option<DispatchWitness>> = const {
        std::cell::RefCell::new(None)
    };
}

/// Attribute commitments to a fixture while its synchronous constructor runs.
///
/// Tests that call legacy constructors without going through a tool request
/// can own their commitments here, even when the constructor accepts no witness.
/// Production defaults stay unchanged. Only this thread's constructions inherit
/// the witness, and unwinding restores the prior scope.
#[cfg(feature = "test-support")]
pub fn with_fixture_dispatch_witness<T>(construct: impl FnOnce() -> T) -> T {
    struct Restore(Option<DispatchWitness>);

    impl Drop for Restore {
        fn drop(&mut self) {
            FIXTURE_WITNESS.with(|slot| slot.replace(self.0.take()));
        }
    }

    let prior = FIXTURE_WITNESS.with(|slot| slot.replace(Some(DispatchWitness::armed())));
    let _restore = Restore(prior);
    construct()
}

/// How many dispatch commitments this process made under a detached witness.
pub fn unattributed_commit_count() -> u64 {
    UNATTRIBUTED_COMMITS.load(Ordering::SeqCst)
}

/// One request's witness. Clones share it.
///
/// Equality is always true and it is never serialized: it describes the
/// request in flight, not the identity it rides in, so it must not make two
/// otherwise equal identities differ or reach a durable record.
#[derive(Clone)]
pub struct DispatchWitness(
    Kind,
    #[cfg(feature = "test-support")] Option<Arc<FixtureOrigin>>,
);

#[cfg(feature = "test-support")]
struct FixtureOrigin {
    thread: String,
    backtrace: std::backtrace::Backtrace,
}

impl Default for DispatchWitness {
    fn default() -> Self {
        Self::detached()
    }
}

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
        Self(
            Kind::Armed(Arc::new(AtomicBool::new(false))),
            #[cfg(feature = "test-support")]
            None,
        )
    }

    /// A witness nobody reads: for a commitment made outside any tool
    /// request (a recovery pass, a test that drives a plane directly). Every
    /// tool request, keyed or not, is armed instead, so in a running module a
    /// commit under this witness means a site lost its request's witness.
    pub fn detached() -> Self {
        #[cfg(feature = "test-support")]
        if let Some(witness) = FIXTURE_WITNESS.with(|slot| slot.borrow().clone()) {
            return witness;
        }
        Self(
            Kind::Detached,
            #[cfg(feature = "test-support")]
            Some(Arc::new(FixtureOrigin {
                thread: std::thread::current()
                    .name()
                    .unwrap_or("unnamed")
                    .to_owned(),
                backtrace: std::backtrace::Backtrace::force_capture(),
            })),
        )
    }

    /// A witness for a commitment no tool request's settlement depends on:
    /// one made by work that is itself outside any plane a request's commit
    /// evidence covers (a browser launch recording its own intent). Its
    /// commits are neither attributed nor counted as unattributed, so they do
    /// not make concurrent calls read as "may have run".
    pub fn outside_tool_calls() -> Self {
        Self(
            Kind::OutsideToolCalls,
            #[cfg(feature = "test-support")]
            None,
        )
    }

    /// Record that a dispatch was committed for this request. Call it at
    /// every commit point, detached or not: a detached witness counts the
    /// commit as one no request can claim.
    #[cfg_attr(feature = "test-support", track_caller)]
    pub fn mark_committed(&self) {
        match &self.0 {
            Kind::Armed(flag) => flag.store(true, Ordering::SeqCst),
            Kind::Detached => {
                // The dev-dependency feature makes rejection unconditional:
                // no test ordering or setup flag can leave a fixture unguarded.
                // Reject before counting so the guard's own panic test cannot
                // contaminate a concurrently running consent test's evidence.
                #[cfg(feature = "test-support")]
                self.reject_detached_fixture();
                UNATTRIBUTED_COMMITS.fetch_add(1, Ordering::SeqCst);
            }
            Kind::OutsideToolCalls => {}
        }
    }

    /// Whether a dispatch was committed for this request.
    pub fn committed(&self) -> bool {
        matches!(&self.0, Kind::Armed(flag) if flag.load(Ordering::SeqCst))
    }

    #[cfg(feature = "test-support")]
    #[track_caller]
    fn reject_detached_fixture(&self) {
        let origin = self.1.as_ref().expect("detached witness has its origin");
        panic!(
            "detached dispatch witness committed at {}; fixture created by {}:\n{}\ncommit stack:\n{}",
            std::panic::Location::caller(),
            origin.thread,
            origin.backtrace,
            std::backtrace::Backtrace::force_capture(),
        );
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

#[cfg(all(test, feature = "test-support"))]
mod fixture_scope_tests {
    use super::{with_fixture_dispatch_witness, DispatchWitness};

    fn assert_guard_rejects_detached() {
        let error = std::panic::catch_unwind(|| DispatchWitness::detached().mark_committed())
            .expect_err("a detached fixture must still trip the guard");
        let message = error.downcast_ref::<String>().unwrap();
        assert!(message.contains("detached dispatch witness committed at"));
    }

    #[test]
    fn fixture_scope_does_not_arm_another_thread() {
        with_fixture_dispatch_witness(|| {
            let witness = DispatchWitness::detached();
            witness.mark_committed();
            assert!(witness.committed());
            std::thread::spawn(assert_guard_rejects_detached)
                .join()
                .unwrap();
        });
    }

    #[test]
    fn fixture_scope_restores_after_unwind() {
        let error = std::panic::catch_unwind(|| {
            with_fixture_dispatch_witness(|| {
                let witness = DispatchWitness::detached();
                witness.mark_committed();
                assert!(witness.committed());
                panic!("fixture construction failed");
            });
        });
        assert!(error.is_err());
        assert_guard_rejects_detached();
    }
}
