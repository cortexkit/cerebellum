//! Bounded blocking-worker capacity, shared by the computer and browser
//! planes.
//!
//! Each plane runs its blocking platform or Chrome work on its own pool of
//! permits. A call takes one work permit and one release permit, atomically,
//! when it acquires its execution lane, and keeps each until the job holding
//! it really ends. With no pair free the call is refused before anything is
//! dispatched, so a run of stuck threads cannot grow without bound.

use std::sync::{Arc, Mutex};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// The blocking-worker pool of one plane.
pub(crate) struct PermitPool {
    permits: Arc<Semaphore>,
}

impl PermitPool {
    pub(crate) fn new(size: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(size)),
        }
    }

    /// One work permit and one release permit, taken together or not at all.
    pub(crate) fn try_call(&self) -> Option<CallPermits> {
        let mut both = Arc::clone(&self.permits).try_acquire_many_owned(2).ok()?;
        let release = both.split(1)?;
        Some(CallPermits {
            _work: Arc::new(both),
            release: Mutex::new(Some(release)),
        })
    }

    /// One work permit for a single blocking query outside a call's pair,
    /// such as a computer target-resolution query.
    pub(crate) fn try_resolution(&self) -> Option<Arc<OwnedSemaphorePermit>> {
        Arc::clone(&self.permits)
            .try_acquire_owned()
            .ok()
            .map(Arc::new)
    }

    #[cfg(test)]
    pub(crate) fn available(&self) -> usize {
        self.permits.available_permits()
    }
}

/// A call's permits. The work permit is shared by each of the call's blocking
/// jobs, which run one after another, and is returned only when the last job
/// holding it really ends. The release permit moves into the held-input
/// release job, if the call registers one.
pub(crate) struct CallPermits {
    _work: Arc<OwnedSemaphorePermit>,
    release: Mutex<Option<OwnedSemaphorePermit>>,
}

impl CallPermits {
    pub(crate) fn take_release(&self) -> Option<OwnedSemaphorePermit> {
        self.release.lock().unwrap().take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_call_takes_a_pair_or_nothing_and_returns_both_when_dropped() {
        let pool = PermitPool::new(3);
        let first = pool.try_call().expect("a free pair");
        assert_eq!(pool.available(), 1);
        assert!(pool.try_call().is_none(), "one permit is not a pair");
        assert_eq!(pool.available(), 1, "a refused call holds nothing");
        let release = first.take_release().expect("the release permit");
        drop(first);
        assert_eq!(pool.available(), 2, "the work permit returns on its own");
        drop(release);
        assert_eq!(pool.available(), 3);
    }
}
