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
pub type QueryProvider =
    Arc<dyn Fn([f64; 2], Instant) -> Result<Option<u32>, &'static str> + Send + Sync>;
static PROVIDER: Mutex<Option<QueryProvider>> = Mutex::new(None);
pub type PrewarmProvider = Arc<dyn Fn(Instant) -> Result<(), &'static str> + Send + Sync>;
static PREWARM_PROVIDER: Mutex<Option<PrewarmProvider>> = Mutex::new(None);

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

/// A readiness barrier, not a hit test or a drawing command. The helper
/// acknowledges the ID only after its AppKit main loop is running.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareRequest {
    pub helper_ready_id: u64,
}

pub fn answer_prepare_request(
    request: PrepareRequest,
    ready: impl FnOnce() -> bool,
    replies: &mut impl Write,
) -> bool {
    if request.helper_ready_id == 0 {
        return false;
    }
    if !ready() {
        return true;
    }
    write_reply(request.helper_ready_id, None, replies)
}

fn write_reply(id: u64, window: Option<u32>, replies: &mut impl Write) -> bool {
    let Ok(mut bytes) = serde_json::to_vec(&Reply {
        pointer_query_id: id,
        window,
    }) else {
        return false;
    };
    bytes.push(b'\n');
    replies.write_all(&bytes).is_ok()
}

/// Handle one helper request without tying the input loop's lifetime to query
/// latency. `None` means the main thread did not answer in time; `Some(None)`
/// is a completed hit test with no recipient. Only invalid input or a failed
/// reply write ends the input loop.
pub fn answer_request(
    request: Request,
    answer: impl FnOnce([f64; 2]) -> Option<Option<u32>>,
    replies: &mut impl Write,
) -> bool {
    if request.pointer_query_id == 0 || !request.point.iter().all(|v| v.is_finite()) {
        return false;
    }
    let Some(window) = answer(request.point) else {
        return true;
    };
    write_reply(request.pointer_query_id, window, replies)
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
        if !point.iter().all(|v| v.is_finite()) {
            return Err("mouse-down recipient helper query point invalid");
        }
        self.request(timeout, |id| Request {
            pointer_query_id: id,
            point,
        })
    }

    pub fn wait_ready(&self, timeout: Duration) -> Result<(), &'static str> {
        self.request(timeout, |id| PrepareRequest {
            helper_ready_id: id,
        })
        .and_then(|window| match window {
            None => Ok(()),
            Some(_) => Err("mouse-down recipient helper reply malformed"),
        })
    }

    fn request<T: Serialize>(
        &self,
        timeout: Duration,
        request: impl FnOnce(u64) -> T,
    ) -> Result<Option<u32>, &'static str> {
        let deadline = Instant::now() + timeout;
        let replies = self
            .replies
            .try_lock()
            .map_err(|_| "mouse-down recipient helper query busy")?;
        let id = NEXT_ID
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| "mouse-down recipient helper request ids exhausted")?;
        let mut bytes = serde_json::to_vec(&request(id))
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

pub fn set_provider(provider: Option<QueryProvider>) {
    *PROVIDER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = provider;
}

pub fn set_prewarm_provider(provider: Option<PrewarmProvider>) {
    *PREWARM_PROVIDER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = provider;
}

pub fn prewarm_until(deadline: Instant) -> Result<(), &'static str> {
    let provider = PREWARM_PROVIDER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
        .ok_or("mouse-down recipient helper transport unavailable")?;
    provider(deadline)
}

pub fn window_at(point: [f64; 2]) -> Result<Option<u32>, &'static str> {
    window_at_until(point, Instant::now() + QUERY_TIMEOUT)
}

pub fn window_at_until(point: [f64; 2], deadline: Instant) -> Result<Option<u32>, &'static str> {
    let provider = PROVIDER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
        .ok_or("mouse-down recipient helper transport unavailable")?;
    provider(point, deadline)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_barrier_sends_no_hit_test_or_drawing_and_matches_its_id() {
        struct ReadyAnswer(mpsc::Sender<Result<Reply, &'static str>>);
        impl Write for ReadyAnswer {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                let value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
                assert_eq!(value.as_object().unwrap().len(), 1);
                let id = value["helper_ready_id"].as_u64().unwrap();
                assert!(id > 0);
                self.0
                    .send(Ok(Reply {
                        pointer_query_id: id - 1,
                        window: Some(99),
                    }))
                    .unwrap();
                let mut response = Vec::new();
                assert!(answer_prepare_request(
                    PrepareRequest {
                        helper_ready_id: id
                    },
                    || true,
                    &mut response
                ));
                self.0
                    .send(Ok(serde_json::from_slice(&response).unwrap()))
                    .unwrap();
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let (tx, rx) = mpsc::channel();
        let client = Client::new(Arc::new(Mutex::new(Box::new(ReadyAnswer(tx)))), rx);
        assert_eq!(client.wait_ready(QUERY_TIMEOUT), Ok(()));
    }

    #[test]
    fn unreadiness_sends_no_reply_and_invalid_readiness_stops_the_loop() {
        let mut replies = Vec::new();
        assert!(answer_prepare_request(
            PrepareRequest { helper_ready_id: 1 },
            || false,
            &mut replies
        ));
        assert!(replies.is_empty());
        assert!(!answer_prepare_request(
            PrepareRequest { helper_ready_id: 0 },
            || panic!("invalid ID"),
            &mut replies
        ));
        assert!(replies.is_empty());
    }

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
    fn missing_transport_refuses_before_a_query_can_be_sent() {
        assert_eq!(
            window_at([1.0, 2.0]),
            Err("mouse-down recipient helper transport unavailable")
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

    #[test]
    fn slow_answer_does_not_end_the_helper_input_loop() {
        let mut replies = Vec::new();
        let mut queries = 0;
        for id in [1, 2] {
            if !answer_request(
                Request {
                    pointer_query_id: id,
                    point: [10.0, 20.0],
                },
                |_| {
                    queries += 1;
                    if id == 1 {
                        None
                    } else {
                        Some(Some(42))
                    }
                },
                &mut replies,
            ) {
                break;
            }
        }
        assert_eq!(
            queries, 2,
            "the next request must survive a slow main-thread answer"
        );
        let reply: Reply = serde_json::from_slice(&replies).unwrap();
        assert_eq!(reply.pointer_query_id, 2);
        assert_eq!(reply.window, Some(42));
    }

    #[test]
    fn invalid_helper_request_ends_the_loop_without_querying() {
        for (id, point) in [(0, [1.0, 2.0]), (1, [f64::NAN, 2.0])] {
            assert!(!answer_request(
                Request {
                    pointer_query_id: id,
                    point
                },
                |_| panic!("invalid request must not query AppKit"),
                &mut Vec::new()
            ));
        }
    }

    #[test]
    fn a_closed_reply_pipe_still_ends_the_helper_input_loop() {
        struct Closed;
        impl Write for Closed {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(!answer_request(
            Request {
                pointer_query_id: 1,
                point: [1.0, 2.0]
            },
            |_| Some(Some(77)),
            &mut Closed
        ));
    }
}
