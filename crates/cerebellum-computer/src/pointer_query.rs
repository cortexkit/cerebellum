//! Bounded private cursor-helper mouse-down recipient requests. A reply is
//! useful only for its own request; a late answer cannot authorize a later post.

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    mpsc, Arc, Mutex,
};
use std::time::{Duration, Instant};

pub const QUERY_TIMEOUT: Duration = Duration::from_millis(50);
pub const MAX_REPLY_BYTES: u64 = 512;
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static HELPER: Mutex<Option<Arc<Client>>> = Mutex::new(None);

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub pointer_query_id: u64,
    pub point: [f64; 2],
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub pointer_query_id: u64,
    pub window: Option<u32>,
}

pub struct Client {
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    replies: Mutex<mpsc::Receiver<Result<Reply, &'static str>>>,
}

impl Client {
    /// The writer must be nonblocking: waiting on a full helper pipe must not
    /// extend the query deadline. Visual and query writes share the same lock.
    pub fn new(
        writer: Arc<Mutex<Box<dyn Write + Send>>>,
        replies: mpsc::Receiver<Result<Reply, &'static str>>,
    ) -> Self {
        Self {
            writer,
            replies: Mutex::new(replies),
        }
    }

    pub fn window_at(
        &self,
        point: [f64; 2],
        timeout: Duration,
    ) -> Result<Option<u32>, &'static str> {
        let deadline = Instant::now() + timeout;
        let replies = self
            .replies
            .try_lock()
            .map_err(|_| "mouse-down recipient helper query busy")?;
        let id = NEXT_ID
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| "mouse-down recipient helper request ids exhausted")?;
        if !point.iter().all(|v| v.is_finite()) {
            return Err("mouse-down recipient helper query point invalid");
        }
        let mut bytes = serde_json::to_vec(&Request {
            pointer_query_id: id,
            point,
        })
        .map_err(|_| "mouse-down recipient helper request encoding failed")?;
        bytes.push(b'\n');
        self.writer
            .try_lock()
            .map_err(|_| "mouse-down recipient helper pipe busy")?
            .write_all(&bytes)
            .map_err(|_| "mouse-down recipient helper request write failed")?;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let reply = replies
                .recv_timeout(remaining)
                .map_err(|error| match error {
                    mpsc::RecvTimeoutError::Timeout => {
                        "mouse-down recipient helper reply timed out"
                    }
                    mpsc::RecvTimeoutError::Disconnected => {
                        "mouse-down recipient helper disconnected"
                    }
                })??;
            if reply.pointer_query_id != id {
                if Instant::now() >= deadline {
                    return Err("mouse-down recipient helper reply timed out");
                }
                continue;
            }
            if Instant::now() >= deadline {
                return Err("mouse-down recipient helper reply timed out");
            }
            if reply.window == Some(0) {
                return Err("mouse-down recipient helper reply malformed");
            }
            return Ok(reply.window);
        }
    }
}

pub fn set_helper(client: Option<Arc<Client>>) {
    *HELPER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = client;
}

pub fn window_at(point: [f64; 2]) -> Result<Option<u32>, &'static str> {
    let helper = HELPER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
        .ok_or("mouse-down recipient helper unavailable")?;
    helper.window_at(point, QUERY_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Answer(mpsc::Sender<Result<Reply, &'static str>>);
    impl Write for Answer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let request: Request = serde_json::from_slice(bytes).unwrap();
            self.0
                .send(Ok(Reply {
                    pointer_query_id: request.pointer_query_id - 1,
                    window: Some(99),
                }))
                .unwrap();
            self.0
                .send(Ok(Reply {
                    pointer_query_id: request.pointer_query_id,
                    window: Some(42),
                }))
                .unwrap();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn stale_reply_is_discarded_instead_of_authorizing_the_next_query() {
        let (tx, rx) = mpsc::channel();
        let client = Client::new(Arc::new(Mutex::new(Box::new(Answer(tx)))), rx);
        for _ in 0..2 {
            assert_eq!(client.window_at([10.0, 20.0], QUERY_TIMEOUT), Ok(Some(42)));
        }
    }

    #[test]
    fn timeout_and_dead_helper_refuse_at_the_reply_step() {
        let (tx, rx) = mpsc::channel();
        let client = Client::new(Arc::new(Mutex::new(Box::new(Vec::<u8>::new()))), rx);
        assert_eq!(
            client.window_at([1.0, 2.0], Duration::ZERO),
            Err("mouse-down recipient helper reply timed out")
        );
        drop(tx);
        assert_eq!(
            client.window_at([1.0, 2.0], QUERY_TIMEOUT),
            Err("mouse-down recipient helper disconnected")
        );
    }

    #[test]
    fn no_helper_refuses_before_a_query_can_be_sent() {
        assert_eq!(
            window_at([1.0, 2.0]),
            Err("mouse-down recipient helper unavailable")
        );
    }

    #[test]
    fn malformed_reply_refuses() {
        let (tx, rx) = mpsc::channel();
        tx.send(Err("mouse-down recipient helper reply malformed"))
            .unwrap();
        let client = Client::new(Arc::new(Mutex::new(Box::new(Vec::<u8>::new()))), rx);
        assert_eq!(
            client.window_at([1.0, 2.0], QUERY_TIMEOUT),
            Err("mouse-down recipient helper reply malformed")
        );
    }
}
