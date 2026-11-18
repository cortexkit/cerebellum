//! `config.gate` over the module's existing channel-0 connection. The SDK's
//! session driver is private to its own transport; the wire bodies are shared.

use std::{path::Path, time::Duration};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use subc_client_rs::config::*;
use subc_protocol::{ErrorBody, Frame, FrameType};
use tokio::sync::{mpsc, Notify};

use super::{config_apply, config_declaration, config_review, LiveSettings, StartupSettings};
use crate::scope_watch::{ControlAnswer, ControlRequests};
use crate::{control_flags, send, ModuleError};

// Separate from scope queries, registration claims, and operator confirmation.
const FIRST_CONFIG_CORR: u64 = 1 << 56;
const CONTROL_DEADLINE: Duration = Duration::from_secs(5);

pub(crate) struct Session {
    requests: ControlRequests,
    changed: Notify,
    version: u8,
}

impl Session {
    pub(crate) fn new(version: u8) -> Self {
        Self {
            requests: ControlRequests::starting_at(FIRST_CONFIG_CORR),
            changed: Notify::new(),
            version,
        }
    }

    /// Responses and change hints may be handled while an unrelated route
    /// handler is awaiting its own control response.
    pub(crate) fn take(&self, frame: &Frame) -> bool {
        if frame.header.channel != 0 || frame.header.epoch != 0 || frame.header.ver != self.version
        {
            return false;
        }
        match frame.header.ty {
            FrameType::Response | FrameType::Error
                if frame.header.corr >= FIRST_CONFIG_CORR && frame.header.corr < (1 << 63) =>
            {
                if let Ok(body) = serde_json::from_slice(&frame.body) {
                    let answer = if frame.header.ty == FrameType::Response {
                        ControlAnswer::Response(body)
                    } else {
                        ControlAnswer::Error(body)
                    };
                    self.requests.deliver(frame.header.corr, answer);
                }
                true
            }
            FrameType::Push if is_op(frame, CONFIG_CHANGED_OP) => {
                if serde_json::from_slice::<ConfigChanged>(&frame.body)
                    .is_ok_and(|hint| hint.project_id.is_none())
                {
                    self.changed.notify_one();
                }
                true
            }
            _ => false,
        }
    }

    pub(crate) fn is_review(&self, frame: &Frame) -> bool {
        frame.header.channel == 0
            && frame.header.epoch == 0
            && frame.header.ver == self.version
            && frame.header.ty == FrameType::Request
            && is_op(frame, CONFIG_REVIEW_OP)
    }

    pub(crate) async fn review(
        &self,
        writer: &mpsc::Sender<Frame>,
        frame: Frame,
        module_id: &str,
    ) -> Result<(), ModuleError> {
        let module_id = module_id.to_owned();
        let corr = frame.header.corr;
        let (ty, body) =
            tokio::task::spawn_blocking(move || match serde_json::from_slice(&frame.body) {
                Ok(request) => (
                    FrameType::Response,
                    serde_json::to_vec(&config_review(&module_id, request)),
                ),
                Err(_) => (
                    FrameType::Error,
                    serde_json::to_vec(&ErrorBody::new(
                        "invalid_request",
                        "invalid config.review snapshots",
                    )),
                ),
            })
            .await
            .map_err(|error| ModuleError::Message(error.to_string()))?;
        let reply = Frame::build_with_version(
            self.version,
            ty,
            control_flags(),
            0,
            0,
            corr,
            body.map_err(ModuleError::Json)?,
        )
        .map_err(|error| ModuleError::Message(error.to_string()))?;
        send(writer, reply).await
    }

    pub(crate) async fn initial(
        &self,
        writer: &mpsc::Sender<Frame>,
        path: &Path,
    ) -> (StartupSettings, Option<ConfigAppliedRequest>) {
        let mut fetch = false;
        if let Some(declaration) = config_declaration(path) {
            // The daemon consumes the one declaration even if it refuses it.
            fetch = self
                .call::<serde_json::Value>(writer, &declaration)
                .await
                .is_ok();
        }
        loop {
            if fetch {
                if let Ok(reply) = self.get(writer).await {
                    let mut view = reply.pending.or_else(|| reply.active.clone());
                    while let Some(candidate) = view {
                        let startup = StartupSettings::from_view(&candidate);
                        let report = report(
                            &candidate,
                            startup.as_ref().map(|_| ()).map_err(Clone::clone),
                        );
                        if let Ok(startup) = startup {
                            return (startup, report);
                        }
                        if let Some(report) = report {
                            let _ = self.call::<serde_json::Value>(writer, &report).await;
                            // The first valid view freezes the restart-only settings.
                            // If this replacement was unusable, recover the last approved view.
                            view = reply
                                .active
                                .clone()
                                .filter(|active| active.status == ConfigStatus::Active);
                        } else {
                            break;
                        }
                    }
                }
            }
            self.changed.notified().await;
            fetch = true;
        }
    }

    pub(crate) async fn live(
        &self,
        writer: &mpsc::Sender<Frame>,
        mut pending_report: Option<ConfigAppliedRequest>,
        apply: impl Fn(LiveSettings),
    ) {
        loop {
            let mut changed_while_reporting = false;
            if let Some(report) = pending_report.take() {
                while matches!(self.call::<serde_json::Value>(writer, &report).await, Err(Some(code)) if code == "anchor_pending")
                {
                    self.changed.notified().await;
                    changed_while_reporting = true;
                }
            }
            if !changed_while_reporting {
                self.changed.notified().await;
            }
            let Ok(reply) = self.get(writer).await else {
                continue;
            };
            let Some(view) = reply.pending.or(reply.active) else {
                continue;
            };
            let result = config_apply(&view).map(&apply);
            pending_report = report(&view, result);
        }
    }

    async fn get(&self, writer: &mpsc::Sender<Frame>) -> Result<ConfigGetReply, Option<String>> {
        let reply = self
            .call::<ConfigGetReply>(writer, &ConfigGetRequest::new())
            .await?;
        if reply.pending.as_ref().is_some_and(|view| {
            view.status != ConfigStatus::Pending
                || view.attempt.is_none()
                || view.project_id.is_some()
        }) || reply.active.as_ref().is_some_and(|view| {
            !matches!(view.status, ConfigStatus::Active | ConfigStatus::Unstamped)
                || view.project_id.is_some()
        }) {
            return Err(None);
        }
        Ok(reply)
    }

    async fn call<T: DeserializeOwned>(
        &self,
        writer: &mpsc::Sender<Frame>,
        request: &impl Serialize,
    ) -> Result<T, Option<String>> {
        match self
            .requests
            .request_with_version(writer, request, CONTROL_DEADLINE, self.version)
            .await
        {
            Some(ControlAnswer::Response(body)) => serde_json::from_value(body).map_err(|_| None),
            Some(ControlAnswer::Error(body)) => Err(body
                .get("code")
                .and_then(|code| code.as_str())
                .map(str::to_owned)),
            None => Err(None),
        }
    }
}

fn report(view: &ConfigView, result: Result<(), String>) -> Option<ConfigAppliedRequest> {
    if view.status != ConfigStatus::Pending {
        return None;
    }
    let (result, reasons) = match result {
        Ok(()) => (ConfigApplyResult::Ack, vec![]),
        Err(reason) => (ConfigApplyResult::Nack, vec![reason]),
    };
    Some(ConfigAppliedRequest::new(
        view.generation,
        view.attempt?,
        result,
        reasons,
    ))
}

fn is_op(frame: &Frame, expected: &str) -> bool {
    #[derive(Deserialize)]
    struct Op<'a> {
        op: &'a str,
    }
    serde_json::from_slice::<Op<'_>>(&frame.body).is_ok_and(|body| body.op == expected)
}
