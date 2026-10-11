//! A browser conversation owns one session, so its calls share one execution
//! lane. The lane includes authorization and consent: a successor must observe
//! the page left by its predecessor, not the page before a person approved it.

use std::cell::RefCell;
use std::future::Future;

use cerebellum_core::identity::RouteSurface;
use cerebellum_core::journal::message_position_from_request_member;
use serde_json::Value;
use subc_protocol::Frame;

use crate::call_queue::{ConversationPosition, LaneGuard};
use crate::Planes;

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
) -> Result<Option<LaneGuard>, &'static str> {
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
    let mut drain = planes.drain_signal.subscribe();
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err("cancelled"),
        _ = drain.wait_for(|draining| *draining) => Err("module_draining"),
        (guard, _) = ticket.acquire() => Ok(Some(guard)),
    }
}
