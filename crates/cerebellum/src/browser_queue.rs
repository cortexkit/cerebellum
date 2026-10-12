//! A browser conversation owns one session, so its calls share one execution
//! lane. The lane includes authorization and consent: a successor must observe
//! the page left by its predecessor, not the page before a person approved it.
//!
//! A session whose operation outlived its call is in execution quarantine:
//! calls that would drive it are refused at once rather than queued behind
//! the worker that still holds the lane, except a close of that session,
//! which bypasses the lane to end it. A session whose page may still hold a
//! pressed key or button is in held-input quarantine: an input call first
//! retries the paired release, and is refused if that cannot be confirmed.

use std::cell::RefCell;
use std::future::Future;
use std::time::Duration;

use cerebellum_core::identity::RouteSurface;
use cerebellum_core::journal::message_position_from_request_member;
use serde_json::{json, Value};
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

/// How often a queued call checks again whether its session has entered
/// execution quarantine; nothing announces that.
const QUARANTINE_POLL: Duration = Duration::from_millis(50);

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum QueueRefusal {
    Cancelled,
    Draining,
    WaitExpired,
    /// The session this call would drive is quarantined. Nothing was
    /// dispatched for the call.
    TargetBusy {
        /// The browser capability whose result vocabulary the reply uses.
        capability: &'static str,
        step: &'static str,
        /// `held_input_unconfirmed` for held-input quarantine; absent for
        /// execution quarantine.
        reason: Option<&'static str>,
        /// The stuck action, or the refused input call.
        call: String,
    },
}

impl QueueRefusal {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::Draining => "module_draining",
            Self::WaitExpired => "queue_wait_expired",
            Self::TargetBusy { .. } => "target_busy",
        }
    }

    pub(crate) fn remedy(&self) -> &'static str {
        match self {
            Self::WaitExpired => "an earlier action in this conversation is still running; nothing was dispatched for this call; retry",
            Self::TargetBusy { reason: Some(_), .. } => crate::browser_session::HELD_INPUT_REMEDY,
            Self::TargetBusy { reason: None, .. } => "a browser operation on this session is still running after its call ended; nothing was dispatched for this call; retry later, or close the session",
            _ => "the queued browser call ended before authorization or execution",
        }
    }

    /// The capability and Response body of a refusal that is answered as a
    /// result of that capability rather than as a route error.
    pub(crate) fn response_body(&self) -> Option<(&'static str, Value)> {
        let Self::TargetBusy {
            capability,
            step,
            reason,
            call,
        } = self
        else {
            return None;
        };
        let mut detail = json!({"dispatched": false, "step": step, "call": call});
        if let Some(reason) = reason {
            detail["reason"] = json!(reason);
            detail["held_state"] = json!("unknown");
        }
        Some((
            capability,
            json!({"outcome": "target_busy", "detail": detail, "remedy": self.remedy()}),
        ))
    }
}

/// A call that drives the conversation's own browser session.
#[derive(Clone)]
struct SessionCall {
    route_key: String,
    capability: &'static str,
    /// Sends input to the page, so held-input quarantine applies to it.
    input: bool,
    /// For a close, the session it names.
    close_session: Option<String>,
}

/// Capabilities that drive the session's browser. Other calls that share
/// the lane (launch, grants, the person's own browser) are not refused for a
/// quarantined session.
fn session_capability(name: &str) -> Option<&'static str> {
    [
        crate::browser::NAVIGATE,
        crate::browser::SNAPSHOT,
        crate::browser::CLICK,
        crate::browser::TYPE,
        crate::browser::SCREENSHOT,
        crate::browser::CLICK_POINT,
        crate::browser::WAIT_FOR,
        crate::browser_session::BROWSER_CLOSE,
        crate::management::PRESENT,
        crate::management::RESUME,
        crate::management::IMPORT_LOGIN,
    ]
    .into_iter()
    .find(|capability| *capability == name)
}

fn session_call(frame: &Frame, planes: &Planes) -> Option<SessionCall> {
    let facts = planes
        .routes
        .get(frame.header.channel, frame.header.epoch)?;
    let body: Value = serde_json::from_slice(&frame.body).ok()?;
    let (capability, arguments) = match facts.surface {
        RouteSurface::Tools => {
            let name = body.get("name")?.as_str()?;
            let arguments = body.get("arguments").cloned().unwrap_or(Value::Null);
            if name == crate::flat_tools::BROWSER_USE {
                if arguments["browser"].as_str() == Some("user") {
                    return None;
                }
                let action = arguments.get("action")?.as_str()?;
                let capability =
                    crate::flat_tools::browser_capability(action).or(match action {
                        "present" => Some(crate::management::PRESENT),
                        "resume" => Some(crate::management::RESUME),
                        "import_login" => Some(crate::management::IMPORT_LOGIN),
                        _ => None,
                    })?;
                (session_capability(capability)?, arguments)
            } else {
                (session_capability(name)?, arguments)
            }
        }
        RouteSurface::Management => (
            session_capability(body.get("method")?.as_str()?)?,
            body.get("params").cloned().unwrap_or(Value::Null),
        ),
        RouteSurface::Unsupported => return None,
    };
    Some(SessionCall {
        route_key: facts.identity.conversation_key.clone(),
        capability,
        input: [
            crate::browser::CLICK,
            crate::browser::TYPE,
            crate::browser::CLICK_POINT,
        ]
        .contains(&capability),
        close_session: (capability == crate::browser_session::BROWSER_CLOSE)
            .then(|| arguments["browser_session_id"].as_str().map(str::to_owned))
            .flatten(),
    })
}

/// What execution quarantine means for one call.
enum Quarantined {
    /// A close of the quarantined session runs now, outside the lane that
    /// the stuck worker still holds.
    Bypass,
    Refuse(QueueRefusal),
}

fn execution_quarantine(call: &SessionCall, planes: &Planes) -> Option<Quarantined> {
    let quarantine = planes.sessions.execution_quarantine(&call.route_key)?;
    Some(
        if call.close_session.as_deref() == Some(quarantine.browser_session_id.as_str()) {
            Quarantined::Bypass
        } else {
            Quarantined::Refuse(QueueRefusal::TargetBusy {
                capability: call.capability,
                step: "queue",
                reason: None,
                call: quarantine.call,
            })
        },
    )
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
/// Status only reads session state and deliberately bypasses the lane, and so
/// does a close of a session in execution quarantine: the stuck worker keeps
/// the lane until it ends, and that close is what ends it.
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
    let bypass = || {
        session_call(frame, planes).is_some_and(|call| {
            matches!(
                execution_quarantine(&call, planes),
                Some(Quarantined::Bypass)
            )
        })
    };
    (queued && !bypass()).then(|| {
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
/// A quarantine refusal is not reported as a route error: every browser
/// capability's result vocabulary includes `target_busy`, so the caller gets
/// it as that capability's result (see `QueueRefusal::response_body`).
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
    let call = session_call(frame, planes);
    match call
        .as_ref()
        .and_then(|call| execution_quarantine(call, planes))
    {
        Some(Quarantined::Refuse(refusal)) => return Err(refusal),
        Some(Quarantined::Bypass) => return Ok(None),
        None => {}
    }
    let cancel = planes
        .cancellations
        .get((frame.header.channel, frame.header.epoch, frame.header.corr))
        .expect("frame reader registered cancellation");
    let quarantine: Option<QuarantineCheck> = call.clone().map(|call| {
        let planes = planes.clone();
        Box::new(move || execution_quarantine(&call, &planes)) as QuarantineCheck
    });
    let Some(guard) = acquire(ticket, cancel, planes.drain_signal.subscribe(), quarantine).await?
    else {
        return Ok(None);
    };
    if let Some(call) = call.filter(|call| call.input) {
        if !release_held_input(&call, planes).await {
            return Err(QueueRefusal::TargetBusy {
                capability: call.capability,
                step: "preflight",
                reason: Some(crate::browser_session::HELD_INPUT_UNCONFIRMED),
                call: call.capability.to_string(),
            });
        }
    }
    Ok(Some(guard))
}

/// With the lane held, so no earlier call of this conversation is running,
/// retry the paired release of any press the page may still hold. Returns
/// whether no press is left held. The release runs on the blocking pool for at
/// most the release budget; one that overruns it is left to finish as a
/// detached worker and the press stays quarantined.
async fn release_held_input(call: &SessionCall, planes: &Planes) -> bool {
    if !planes.sessions.held_input_unconfirmed(&call.route_key) {
        return true;
    }
    let sessions = planes.sessions.clone();
    let route_key = call.route_key.clone();
    let mut release = tokio::task::spawn_blocking(move || {
        sessions.retry_held_release(&route_key, crate::budgets::CDP_RELEASE_MS)
    });
    match tokio::time::timeout(
        Duration::from_millis(crate::budgets::RELEASE_BUDGET_MS),
        &mut release,
    )
    .await
    {
        Ok(released) => released.unwrap_or(false),
        Err(_) => {
            let detached = planes.health.enter_detached_worker();
            tokio::spawn(async move {
                let _detached = detached;
                let _ = release.await;
            });
            false
        }
    }
}

type QuarantineCheck = Box<dyn FnMut() -> Option<Quarantined> + Send>;

async fn acquire(
    ticket: ConversationPosition,
    cancel: crate::CancelHandle,
    mut drain: tokio::sync::watch::Receiver<bool>,
    quarantine: Option<QuarantineCheck>,
) -> Result<Option<LaneGuard>, QueueRefusal> {
    let deadline = ticket.wait_deadline(QUEUE_WAIT_LIMIT);
    let quarantined = async {
        let Some(mut check) = quarantine else {
            return std::future::pending().await;
        };
        loop {
            tokio::time::sleep(QUARANTINE_POLL).await;
            if let Some(quarantined) = check() {
                return quarantined;
            }
        }
    };
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(QueueRefusal::Cancelled),
        _ = drain.wait_for(|draining| *draining) => Err(QueueRefusal::Draining),
        _ = tokio::time::sleep_until(deadline) => Err(QueueRefusal::WaitExpired),
        (guard, _) = ticket.acquire() => Ok(Some(guard)),
        quarantined = quarantined => match quarantined {
            Quarantined::Bypass => Ok(None),
            Quarantined::Refuse(refusal) => Err(refusal),
        },
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
        let queued = tokio::spawn(acquire(ticket, crate::CancelHandle::pending(), drain, None));
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
        let queued = tokio::spawn(acquire(ticket, crate::CancelHandle::pending(), drain, None));
        tokio::task::yield_now().await;
        tokio::time::advance(crate::computer_grants::CONSENT_PARK_LIMIT).await;
        assert!(
            !queued.is_finished(),
            "normal consent must not expire the successor"
        );
        drop(holder);
        drop(
            queued
                .await
                .unwrap()
                .unwrap()
                .expect("the lane is acquired"),
        );
        assert!(queue.is_empty());
        drop(drain_tx);
    }

    #[test]
    fn quarantine_refusals_are_results_of_the_refused_capability() {
        for capability in [
            crate::browser::NAVIGATE,
            crate::browser::SNAPSHOT,
            crate::browser::CLICK,
            crate::browser::TYPE,
            crate::browser::SCREENSHOT,
            crate::browser::CLICK_POINT,
            crate::browser_session::BROWSER_CLOSE,
        ] {
            assert_eq!(session_capability(capability), Some(capability));
            for reason in [None, Some(crate::browser_session::HELD_INPUT_UNCONFIRMED)] {
                let refusal = QueueRefusal::TargetBusy {
                    capability,
                    step: "queue",
                    reason,
                    call: "Input.dispatchMouseEvent".into(),
                };
                assert_eq!(refusal.code(), "target_busy");
                let (named, body) = refusal.response_body().unwrap();
                assert_eq!(named, capability);
                crate::browser::validate_browser_result(capability, &body)
                    .unwrap_or_else(|error| panic!("{capability}: {error} in {body}"));
                assert_eq!(body["outcome"], "target_busy");
                assert_eq!(body["detail"]["dispatched"], false);
                assert_eq!(body["detail"]["call"], "Input.dispatchMouseEvent");
                match reason {
                    Some(reason) => {
                        assert_eq!(body["detail"]["reason"], reason);
                        assert_eq!(body["detail"]["held_state"], "unknown");
                        assert_eq!(body["remedy"], crate::browser_session::HELD_INPUT_REMEDY);
                    }
                    None => assert!(body["detail"].get("reason").is_none(), "{body}"),
                }
            }
        }
        assert!(QueueRefusal::WaitExpired.response_body().is_none());
        assert_eq!(
            session_capability(crate::browser_session::BROWSER_LAUNCH),
            None
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_queued_call_is_refused_or_bypasses_once_its_session_is_quarantined() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        for bypass in [false, true] {
            let queue = ConversationQueue::default();
            let (holder, _) = queue.arrive("conversation".into(), None).acquire().await;
            let ticket = queue.arrive("conversation".into(), None);
            let quarantined = Arc::new(AtomicBool::new(false));
            let seen = Arc::clone(&quarantined);
            let check: QuarantineCheck = Box::new(move || {
                seen.load(Ordering::SeqCst).then(|| {
                    if bypass {
                        Quarantined::Bypass
                    } else {
                        Quarantined::Refuse(QueueRefusal::TargetBusy {
                            capability: crate::browser::NAVIGATE,
                            step: "queue",
                            reason: None,
                            call: "Page.navigate".into(),
                        })
                    }
                })
            });
            let (drain_tx, drain) = tokio::sync::watch::channel(false);
            let queued = tokio::spawn(acquire(
                ticket,
                crate::CancelHandle::pending(),
                drain,
                Some(check),
            ));
            tokio::time::sleep(QUARANTINE_POLL * 3).await;
            assert!(!queued.is_finished(), "a call behind ordinary work waits");
            quarantined.store(true, Ordering::SeqCst);
            tokio::time::sleep(QUARANTINE_POLL * 2).await;
            assert!(queued.is_finished(), "the quarantine was not noticed");
            match queued.await.unwrap() {
                Ok(None) => assert!(bypass),
                Err(refusal) => {
                    assert!(!bypass);
                    assert_eq!(refusal.code(), "target_busy");
                }
                Ok(Some(_)) => panic!("the lane held by the stuck worker was acquired"),
            }
            drop(holder);
            assert!(queue.is_empty(), "the refused call kept its position");
            drop(drain_tx);
        }
    }
}
