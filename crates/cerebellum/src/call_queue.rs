//! Non-blocking message-ordered tickets for conversation and resource lanes.
//!
//! Polling each mutex reservation once at arrival fixes its FIFO position before
//! spawning the caller. Only the caller task awaits it, so consent or platform
//! waits cannot stop the frame reader from handling cancellation or other routes.

use std::collections::{BTreeSet, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use cerebellum_core::journal::{ComputerOrderRecord, ComputerOrdering};
use tokio::sync::{Mutex as AsyncMutex, Notify, OwnedMutexGuard};
use tokio::time::Instant;

pub(crate) const GAP_LIMIT: Duration = Duration::from_millis(1500);
const MESSAGE_RETENTION: Duration = Duration::from_secs(30);
const MESSAGES_PER_CONVERSATION: usize = 128;

type LockFuture = Pin<Box<dyn Future<Output = OwnedMutexGuard<()>> + Send>>;

/// A live queue position, including when the caller has not been spawned yet.
/// Dropping it releases either the acquired lock or its unfulfilled position.
struct Reservation {
    future: LockFuture,
}

impl Reservation {
    fn new(mutex: Arc<AsyncMutex<()>>) -> Self {
        let mut future: LockFuture = Box::pin(mutex.lock_owned());
        if let Poll::Ready(guard) = future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            future = Box::pin(std::future::ready(guard));
        }
        Self { future }
    }
}

type Key = (String, String);

struct Entry {
    mutex: Arc<AsyncMutex<()>>,
    users: usize,
}

#[derive(Default)]
pub(crate) struct Registry(Mutex<HashMap<Key, Entry>>);

/// Counts queued as well as executing calls. A final drop removes the entry
/// under the same map lock as insertion, so there can never be two live locks
/// for one key. Field order releases the lock before removing its map entry.
pub(crate) struct LaneGuard {
    _lock: OwnedMutexGuard<()>,
    _lease: Lease,
}

struct Lease {
    registry: Arc<Registry>,
    key: Key,
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut entries = self.registry.0.lock().unwrap_or_else(|e| e.into_inner());
        let entry = entries.get_mut(&self.key).expect("live queue entry");
        entry.users -= 1;
        if entry.users == 0 {
            entries.remove(&self.key);
        }
    }
}

pub(crate) struct QueuePosition {
    reservation: Reservation,
    lease: Lease,
}

impl QueuePosition {
    pub(crate) async fn acquire(mut self) -> LaneGuard {
        // Borrow the future so cancellation drops the mutex reservation before
        // decrementing the registry's user count. Reversing those drops could
        // remove a lane from the registry while its mutex still has a waiter.
        let lock = self.reservation.future.as_mut().await;
        LaneGuard {
            _lock: lock,
            _lease: self.lease,
        }
    }
}

#[derive(Default)]
pub(crate) struct ConversationQueue {
    conversations: Arc<Registry>,
    messages: Arc<Messages>,
}

#[derive(Default)]
struct Messages(Mutex<HashMap<String, HashMap<String, Arc<Message>>>>);

struct Message {
    state: Mutex<MessageState>,
    changed: Notify,
}

struct MessageState {
    pending: BTreeSet<u32>,
    entered: Option<u32>,
    last_used: Instant,
}

/// The frame reader registers the index but never waits for a predecessor.
/// Unpositioned calls and ready calls from other messages bypass a gap waiter.
/// They enter the lane before that waiter's later calls:
/// arrival order is the only ordering information available between messages.
pub(crate) struct ConversationPosition {
    queue: Option<QueuePosition>,
    conversations: Arc<Registry>,
    conversation: String,
    message: Option<Arc<Message>>,
    index: Option<u32>,
    arrived_at: Instant,
    deadline: Instant,
}

impl ConversationQueue {
    pub(crate) fn arrive(
        &self,
        conversation: String,
        position: Option<subc_protocol::tool_call::MessagePosition>,
    ) -> ConversationPosition {
        let now = Instant::now();
        let index = position.as_ref().map(|position| position.index);
        let mut ticket = ConversationPosition {
            queue: None,
            conversations: self.conversations.clone(),
            conversation: conversation.clone(),
            message: None,
            index,
            arrived_at: now,
            deadline: now + GAP_LIMIT,
        };
        if let Some(position) = position {
            let mut conversations = self.messages.0.lock().unwrap_or_else(|e| e.into_inner());
            let messages = conversations.entry(conversation.clone()).or_default();
            if !messages.contains_key(&position.message_id)
                && messages.len() < MESSAGES_PER_CONVERSATION
            {
                let message = Arc::new(Message {
                    state: Mutex::new(MessageState {
                        pending: BTreeSet::new(),
                        entered: None,
                        last_used: now,
                    }),
                    changed: Notify::new(),
                });
                messages.insert(position.message_id.clone(), message.clone());
                // One expiry task per tracked message, not per call. A weak
                // registry reference lets shutdown discard the cache immediately.
                let registry = Arc::downgrade(&self.messages);
                let key = conversation.clone();
                let id = position.message_id.clone();
                tokio::spawn(async move {
                    loop {
                        let changed = message.changed.notified();
                        tokio::pin!(changed);
                        changed.as_mut().enable();
                        let expiry = {
                            let state = message.state.lock().unwrap_or_else(|e| e.into_inner());
                            if state.pending.is_empty() {
                                state.last_used + MESSAGE_RETENTION
                            } else {
                                Instant::now() + MESSAGE_RETENTION
                            }
                        };
                        tokio::select! {
                            _ = &mut changed => continue,
                            _ = tokio::time::sleep_until(expiry) => {},
                        }
                        let Some(registry) = registry.upgrade() else {
                            break;
                        };
                        let mut conversations =
                            registry.0.lock().unwrap_or_else(|e| e.into_inner());
                        let Some(messages) = conversations.get_mut(&key) else {
                            break;
                        };
                        let state = message.state.lock().unwrap_or_else(|e| e.into_inner());
                        if state.pending.is_empty()
                            && state.last_used.elapsed() >= MESSAGE_RETENTION
                        {
                            messages.remove(&id);
                            if messages.is_empty() {
                                conversations.remove(&key);
                            }
                            break;
                        }
                    }
                });
            }
            if let Some(message) = messages.get(&position.message_id) {
                let mut state = message.state.lock().unwrap_or_else(|e| e.into_inner());
                // Duplicate or late indices cannot undo entry. Retain the
                // supplied index in the returned ordering metadata so callers
                // can record the ignored hint, but use arrival order to execute.
                if state.entered.is_none_or(|entered| position.index > entered)
                    && state.pending.insert(position.index)
                {
                    state.last_used = now;
                    if position.index == 0 || state.entered == position.index.checked_sub(1) {
                        ticket.queue = Some(
                            self.conversations
                                .reserve((conversation.clone(), String::new())),
                        );
                    }
                    ticket.message = Some(message.clone());
                    message.changed.notify_waiters();
                }
            }
        }
        if ticket.message.is_none() {
            // At the message-cache cap, an untracked hint degrades to arrival
            // order rather than allocating without a bound or refusing a call.
            ticket.queue = Some(self.conversations.reserve((conversation, String::new())));
        }
        ticket
    }
}

impl ConversationPosition {
    pub(crate) fn wait_deadline(&self, limit: Duration) -> Instant {
        self.arrived_at + limit
    }

    pub(crate) async fn acquire(mut self) -> (LaneGuard, ComputerOrderRecord) {
        let mut ordering = ComputerOrdering::Arrival;
        if let Some(message) = &self.message {
            let index = self.index.expect("positioned ticket");
            ordering = ComputerOrdering::Position;
            while self.queue.is_none() {
                // Subscribe before inspecting the state so entry/cancellation
                // cannot be lost between checking and beginning to wait.
                let changed = message.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                let wait_for_gap = {
                    let state = message.state.lock().unwrap_or_else(|e| e.into_inner());
                    let lowest = state.pending.first().copied() == Some(index);
                    let predecessor_entered = index == 0 || state.entered == index.checked_sub(1);
                    let gap_expired = Instant::now() >= self.deadline;
                    if lowest && (predecessor_entered || gap_expired) {
                        if !predecessor_entered {
                            ordering = ComputerOrdering::SkippedGap;
                        }
                        self.queue = Some(
                            self.conversations
                                .reserve((self.conversation.clone(), String::new())),
                        );
                        false
                    } else {
                        // A lower arrived index must enter first, even if our
                        // own gap deadline has expired. The 1.5-second timeout
                        // covers missing predecessors, not ones already queued.
                        // Index 0 has no predecessor and never waits for a gap.
                        lowest && !gap_expired
                    }
                };
                if self.queue.is_some() {
                    break;
                }
                if wait_for_gap {
                    tokio::select! {
                        _ = &mut changed => {},
                        _ = tokio::time::sleep_until(self.deadline) => {},
                    }
                } else {
                    changed.await;
                }
            }
        }
        let guard = self
            .queue
            .take()
            .expect("ready conversation position")
            .acquire()
            .await;
        if let Some(message) = self.message.take() {
            let mut state = message.state.lock().unwrap_or_else(|e| e.into_inner());
            let index = self.index.expect("positioned ticket");
            state.pending.remove(&index);
            state.entered = Some(index);
            state.last_used = Instant::now();
            message.changed.notify_waiters();
        }
        (
            guard,
            ComputerOrderRecord {
                message_index: self.index,
                ordering,
            },
        )
    }
}

impl Drop for ConversationPosition {
    fn drop(&mut self) {
        if let Some(message) = &self.message {
            let mut state = message.state.lock().unwrap_or_else(|e| e.into_inner());
            state
                .pending
                .remove(&self.index.expect("positioned ticket"));
            state.last_used = Instant::now();
            message.changed.notify_waiters();
        }
    }
}

impl Registry {
    pub(crate) fn reserve(self: &Arc<Self>, key: Key) -> QueuePosition {
        let mut entries = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let entry = entries.entry(key.clone()).or_insert_with(|| Entry {
            mutex: Arc::new(AsyncMutex::new(())),
            users: 0,
        });
        entry.users += 1;
        QueuePosition {
            reservation: Reservation::new(entry.mutex.clone()),
            lease: Lease {
                registry: self.clone(),
                key,
            },
        }
    }
}

#[cfg(test)]
impl Registry {
    pub(crate) fn is_empty(&self) -> bool {
        self.0.lock().unwrap().is_empty()
    }

    pub(crate) fn has_users(&self, count: usize) -> bool {
        self.0
            .lock()
            .unwrap()
            .values()
            .any(|entry| entry.users == count)
    }
}

#[cfg(test)]
impl ConversationQueue {
    pub(crate) fn is_empty(&self) -> bool {
        self.conversations.is_empty()
    }

    pub(crate) fn has_users(&self, count: usize) -> bool {
        self.conversations.has_users(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn message_tracking_is_capped_with_arrival_fallback() {
        let serializer = ConversationQueue::default();
        let mut tickets = Vec::new();
        for index in 0..=MESSAGES_PER_CONVERSATION {
            tickets.push(serializer.arrive(
                "one".into(),
                Some(subc_protocol::tool_call::MessagePosition::new(
                    format!("m{index}"),
                    2,
                )),
            ));
        }
        assert_eq!(
            serializer.messages.0.lock().unwrap()["one"].len(),
            MESSAGES_PER_CONVERSATION
        );
        let last = tickets.pop().unwrap();
        let (_, order) = last.acquire().await;
        assert_eq!(order.ordering, ComputerOrdering::Arrival);
        assert_eq!(order.message_index, Some(2));
        drop(tickets);
        // Age only the cache's idle timestamp to exercise the real expiry task
        // without waiting 30 seconds or advancing the runtime clock.
        for message in serializer.messages.0.lock().unwrap()["one"].values() {
            message.state.lock().unwrap().last_used = Instant::now() - MESSAGE_RETENTION;
            message.changed.notify_waiters();
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while !serializer.messages.0.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("idle message ids are forgotten after retention");
    }
}
