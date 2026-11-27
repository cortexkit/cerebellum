use super::{Reason, Rejection};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{oneshot, Semaphore};
use tokio::time::{sleep_until, Instant};

const VERIFICATION_TIMEOUT: Duration = Duration::from_secs(1);
const VERIFICATION_SLOTS: usize = 4;

#[derive(Clone)]
pub(in super::super) struct VerificationWorkers(Arc<Semaphore>);

impl VerificationWorkers {
    pub(super) fn new() -> Self {
        Self(Arc::new(Semaphore::new(VERIFICATION_SLOTS)))
    }

    pub(super) async fn run<T: Send + 'static>(
        &self,
        failure: Reason,
        check: impl FnOnce() -> Result<T, Reason> + Send + 'static,
    ) -> Result<T, Rejection> {
        let slot = self
            .0
            .clone()
            .try_acquire_owned()
            .map_err(|_| Rejection::Close)?;
        let (send, receive) = oneshot::channel();
        let deadline = Instant::now() + VERIFICATION_TIMEOUT;
        // Tokio waits for its blocking pool at shutdown. Detach the worker and
        // keep the permit with the check, not with its caller's timed wait.
        std::thread::Builder::new()
            .name("user-browser-verification".into())
            .spawn(move || {
                let outcome = check();
                // If admission timed out, sending drops the evidence and permit
                // here. No worker can continue an abandoned handshake.
                let _ = send.send((outcome, slot));
            })
            .map_err(|_| Rejection::Refuse(failure))?;
        tokio::select! {
            biased;
            _ = sleep_until(deadline) => Err(failure.into()),
            verdict = receive => {
                let (outcome, _slot) = verdict.map_err(|_| Rejection::Refuse(failure))?;
                outcome.map_err(Into::into)
            }
        }
    }
}
