//! A browser conversation owns one session, so its calls share one execution
//! lane. The lane includes authorization and consent: a successor must observe
//! the page left by its predecessor, not the page before a person approved it.

use std::cell::RefCell;
use std::future::Future;
use std::time::Duration;

use cerebellum_core::identity::RouteSurface;
use cerebellum_core::journal::message_position_from_request_member;
use serde_json::Value;
use subc_protocol::Frame;

use crate::call_queue::{ConversationPosition, LaneGuard};
use crate::Planes;

// Preserve a full in-call consent park before giving a predecessor time to
// finish. Reserve 60s for browser work: the login bridge already allows a
// 30s queue + 30s reply wait; this also covers a capped 30s launch plus two
// 5s teardown windows. These are operation budgets, not an outer action timer:
// multi-step CDP actions can reuse their deadline for each step.
const QUEUE_WAIT_LIMIT: Duration = crate::computer_grants::CONSENT_PARK_LIMIT
    .saturating_add(crate::user_browser_bridge::QUEUE_DEADLINE)
    .saturating_add(crate::user_browser_bridge::REPLY_DEADLINE);

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum QueueRefusal {
    Cancelled,
    Draining,
    WaitExpired,
}

impl QueueRefusal {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::Draining => "module_draining",
            Self::WaitExpired => "queue_wait_expired",
        }
    }

    pub(crate) fn remedy(&self) -> &'static str {
        match self {
            Self::WaitExpired => "an earlier action in this conversation is still running; nothing was dispatched for this call; retry",
            _ => "the queued browser call ended before authorization or execution",
        }
    }
}

tokio::task_local! {
    static ARRIVAL: RefCell<Option<ConversationPosition>>;
}

pub(crate) async fn scope<T>(
    arrival: Option<ConversationPosition>,
    future: impl Future<Output = T>,
) -> T {
    ARRIVAL.scope(RefCell::new(arrival), future).await
}

/// Reserve in the frame reader without waiting or checking site authority.
/// Status only reads session state and deliberately bypasses the lane.
pub(crate) fn arrive(frame: &Frame, planes: &Planes) -> Option<ConversationPosition> {
    let facts = planes
        .routes
        .get(frame.header.channel, frame.header.epoch)?;
    let body: Value = serde_json::from_slice(&frame.body).ok()?;
    let queued = match facts.surface {
        RouteSurface::Tools => {
            let name = body.get("name")?.as_str()?;
            if name == crate::flat_tools::BROWSER_USE {
                body["arguments"]["browser"].as_str() == Some("user")
                    || body.get("arguments")?.get("action")?.as_str()? != "status"
            } else {
                name.starts_with("browser.") && name != crate::browser_session::BROWSER_STATUS
            }
        }
        RouteSurface::Management => {
            let method = body.get("method")?.as_str()?;
            method.starts_with("browser.") && method != crate::browser_session::BROWSER_STATUS
        }
        RouteSurface::Unsupported => false,
    };
    queued.then(|| {
        planes.browser_queue.arrive(
            facts.identity.conversation_key,
            message_position_from_request_member(body.get("origin")),
        )
    })
}

/// Only spawned call tasks await tickets. Dropping the acquire future on cancel
/// removes a queued position without authorizing or running the browser action.
/// Report interruption as a route error: browser actions have different frozen
/// result vocabularies, and not all of them have a cancelled result outcome.
pub(crate) async fn enter(
    frame: &Frame,
    planes: &Planes,
) -> Result<Option<LaneGuard>, QueueRefusal> {
    let Some(ticket) = ARRIVAL
        .try_with(|arrival| arrival.borrow_mut().take())
        .ok()
        .flatten()
    else {
        return Ok(None);
    };
    let cancel = planes
        .cancellations
        .get((frame.header.channel, frame.header.epoch, frame.header.corr))
        .expect("frame reader registered cancellation");
    acquire(ticket, cancel, planes.drain_signal.subscribe())
        .await
        .map(Some)
}

async fn acquire(
    ticket: ConversationPosition,
    cancel: crate::CancelHandle,
    mut drain: tokio::sync::watch::Receiver<bool>,
) -> Result<LaneGuard, QueueRefusal> {
    let deadline = ticket.wait_deadline(QUEUE_WAIT_LIMIT);
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(QueueRefusal::Cancelled),
        _ = drain.wait_for(|draining| *draining) => Err(QueueRefusal::Draining),
        _ = tokio::time::sleep_until(deadline) => Err(QueueRefusal::WaitExpired),
        (guard, _) = ticket.acquire() => Ok(guard),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call_queue::ConversationQueue;

    #[tokio::test(start_paused = true)]
    async fn stuck_browser_holder_expires_queued_call_without_dispatch() {
        assert_eq!(QUEUE_WAIT_LIMIT, Duration::from_secs(180));
        let queue = ConversationQueue::default();
        let (holder, _) = queue.arrive("conversation".into(), None).acquire().await;
        let ticket = queue.arrive("conversation".into(), None);
        let scheduling_delay = Duration::from_secs(10);
        tokio::time::advance(scheduling_delay).await;
        let (drain_tx, drain) = tokio::sync::watch::channel(false);
        let queued = tokio::spawn(acquire(ticket, crate::CancelHandle::pending(), drain));
        tokio::task::yield_now().await;
        tokio::time::advance(QUEUE_WAIT_LIMIT - scheduling_delay - Duration::from_millis(1)).await;
        assert!(!queued.is_finished());
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(queued.is_finished(), "queue deadline did not end the call");
        let refusal = queued.await.unwrap().err().unwrap();
        assert_eq!(refusal, QueueRefusal::WaitExpired);
        assert_eq!(refusal.code(), "queue_wait_expired");
        assert!(refusal.remedy().contains("nothing was dispatched"));
        assert!(refusal.remedy().contains("retry"));
        drop(holder);
        assert!(queue.is_empty(), "expired ticket must release its position");
        drop(drain_tx);
    }

    #[tokio::test(start_paused = true)]
    async fn browser_queue_preserves_a_normal_consent_park() {
        let queue = ConversationQueue::default();
        let (holder, _) = queue.arrive("conversation".into(), None).acquire().await;
        let ticket = queue.arrive("conversation".into(), None);
        let (drain_tx, drain) = tokio::sync::watch::channel(false);
        let queued = tokio::spawn(acquire(ticket, crate::CancelHandle::pending(), drain));
        tokio::task::yield_now().await;
        tokio::time::advance(crate::computer_grants::CONSENT_PARK_LIMIT).await;
        assert!(
            !queued.is_finished(),
            "normal consent must not expire the successor"
        );
        drop(holder);
        drop(queued.await.unwrap().unwrap());
        assert!(queue.is_empty());
        drop(drain_tx);
    }
}
