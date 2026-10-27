//! The daemon's channel-zero operator confirmation seam.
//!
//! The module speaks the wire directly. Only a typed confirmed reply grants
//! authority; a missing connection or any other reply leaves background mode.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use subc_protocol::session::{OperatorConfirmReply, OperatorConfirmRequest};
use subc_protocol::{ErrorBody, Frame, FrameType};
use tokio::sync::{mpsc, oneshot};

const SUMMARY: &str = "Let agents bring apps to the front and type into them";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Failure {
    Declined,
    Backoff { retry_after_ms: u64 },
    PresenceUnavailable,
    SummaryInvalid,
    NotPermitted,
    Unsupported,
    TimeLimit { remaining_ms: u64 },
    SettingChanged,
    Cancelled,
}

impl Failure {
    pub(super) fn line(&self) -> String {
        match self {
            Self::Declined => "operator confirmation declined".into(),
            Self::Backoff { retry_after_ms } => format!("operator confirmation is on hold; retry after {retry_after_ms} ms"),
            Self::PresenceUnavailable => "operator presence is unavailable (including while the screen is locked)".into(),
            Self::SummaryInvalid => "the operator confirmation summary was invalid".into(),
            Self::NotPermitted => "operator confirmation is not permitted on this route".into(),
            Self::Unsupported => "operator confirmation is unsupported on this connection".into(),
            Self::TimeLimit { remaining_ms } => format!("the call's time limit has {remaining_ms} ms remaining, less than the 290000 ms operator confirmation allowance"),
            Self::SettingChanged => "the app-use setting changed while confirmation was waiting".into(),
            Self::Cancelled => "the call requesting operator confirmation was cancelled".into(),
        }
    }
}

pub(crate) struct Wire {
    next_corr: AtomicU64,
    pending: Mutex<HashMap<u64, oneshot::Sender<Frame>>>,
}

impl Default for Wire {
    fn default() -> Self {
        Self {
            // Scope-description requests use IDs starting at 1 << 40.
            next_corr: AtomicU64::new(1 << 63),
            pending: Mutex::new(HashMap::new()),
        }
    }
}

impl Wire {
    pub(crate) fn deliver(&self, frame: &Frame) -> bool {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&frame.header.corr)
            .is_some_and(|sender| sender.send(frame.clone()).is_ok())
    }

    async fn request(
        self: &Arc<Self>,
        writer: &mpsc::Sender<Frame>,
        route: (u16, u32),
    ) -> Result<(), Failure> {
        let body = serde_json::to_vec(&OperatorConfirmRequest::new(SUMMARY, route.0, route.1))
            .map_err(|_| Failure::SummaryInvalid)?;
        let corr = self.next_corr.fetch_add(1, Ordering::Relaxed);
        let request = Frame::build(FrameType::Request, crate::control_flags(), 0, 0, corr, body)
            .map_err(|_| Failure::PresenceUnavailable)?;
        let cancel = Frame::build(
            FrameType::Cancel,
            crate::control_flags(),
            0,
            0,
            corr,
            Vec::new(),
        )
        .map_err(|_| Failure::PresenceUnavailable)?;
        // Reserve withdrawal capacity before sending: Drop must not lose a
        // cancellation just because the call's egress queue has filled up.
        let withdrawal = writer
            .clone()
            .reserve_owned()
            .await
            .map_err(|_| Failure::PresenceUnavailable)?;
        let (sender, receiver) = oneshot::channel();
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(corr, sender);
        let mut guard = Withdraw {
            wire: Arc::clone(self),
            corr,
            withdrawal: Some((withdrawal, cancel)),
            sent: false,
        };
        writer
            .send(request)
            .await
            .map_err(|_| Failure::PresenceUnavailable)?;
        guard.sent = true;
        let frame = receiver.await.map_err(|_| Failure::PresenceUnavailable)?;
        guard.withdrawal = None;
        decode(&frame)
    }
}

struct Withdraw {
    wire: Arc<Wire>,
    corr: u64,
    withdrawal: Option<(mpsc::OwnedPermit<Frame>, Frame)>,
    sent: bool,
}

impl Drop for Withdraw {
    fn drop(&mut self) {
        self.wire
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.corr);
        if self.sent {
            if let Some((permit, cancel)) = self.withdrawal.take() {
                permit.send(cancel);
            }
        }
    }
}

fn decode(frame: &Frame) -> Result<(), Failure> {
    if frame.header.ty == FrameType::Response {
        return match serde_json::from_slice::<OperatorConfirmReply>(&frame.body) {
            Ok(reply) if reply.outcome == "confirmed" => Ok(()),
            _ => Err(Failure::PresenceUnavailable),
        };
    }
    let error = serde_json::from_slice::<ErrorBody>(&frame.body)
        .map_err(|_| Failure::PresenceUnavailable)?;
    Err(match error.code.as_str() {
        "operator_declined" => {
            let detail = error.detail.unwrap_or_default();
            if detail["reason"] == "backoff" {
                Failure::Backoff {
                    retry_after_ms: detail["retry_after_ms"].as_u64().unwrap_or(30_000),
                }
            } else {
                Failure::Declined
            }
        }
        "operator_summary_invalid" => Failure::SummaryInvalid,
        "operator_request_not_permitted" | "not_registered" => Failure::NotPermitted,
        "unsupported_control_frame" => Failure::Unsupported,
        _ => Failure::PresenceUnavailable,
    })
}

#[derive(Clone)]
pub(crate) struct Call {
    pub(crate) wire: Arc<Wire>,
    pub(crate) writer: mpsc::Sender<Frame>,
    pub(crate) route: (u16, u32),
}

tokio::task_local! {
    pub(crate) static CALL: Call;
}

pub(super) async fn confirm() -> Result<(), Failure> {
    let call = CALL
        .try_with(Clone::clone)
        .map_err(|_| Failure::Unsupported)?;
    tokio::time::timeout(
        super::app_use_approval::CONFIRM_LIMIT,
        call.wire.request(&call.writer, call.route),
    )
    .await
    .unwrap_or(Err(Failure::PresenceUnavailable))
}

#[cfg(test)]
#[path = "operator_confirm_tests.rs"]
mod tests;
