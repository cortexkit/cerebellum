//! What keeps a temporary front inside its bound once the target is in
//! front: checks a keystroke unit makes before each of its own posts.

use crate::platform::{FrontedKeyGuard, ProcessEventRefusal};

/// The per-post checks for a keystroke unit posted while its target is in
/// front: the target is still the frontmost application, and the bracket's
/// deadline has not passed. The unit's cancellation is checked separately
/// by the sequence, before these.
///
/// A post refused here was never made, so the refusal is
/// [`ProcessEventRefusal::Cancelled`], which a reply reads as no post call
/// for this event. Presses the unit already posted are released as on any
/// other stop.
pub struct FrontedKeyChecks<N, F> {
    pub target_pid: u32,
    /// On the bracket's clock, as `now_ms` reads it.
    pub deadline_ms: u64,
    pub now_ms: N,
    pub frontmost_pid: F,
}

impl<N, F> FrontedKeyGuard for FrontedKeyChecks<N, F>
where
    N: FnMut() -> u64,
    F: FnMut() -> Option<u32>,
{
    fn before_post(&mut self, _press: bool) -> Result<(), ProcessEventRefusal> {
        // The focus read can take a moment; the deadline is read after it so
        // nothing that can block separates the deadline check from the post.
        if (self.frontmost_pid)() != Some(self.target_pid) {
            return Err(ProcessEventRefusal::Cancelled);
        }
        if (self.now_ms)() >= self.deadline_ms {
            return Err(ProcessEventRefusal::Cancelled);
        }
        Ok(())
    }
}
