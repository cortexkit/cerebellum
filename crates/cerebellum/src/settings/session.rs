//! `config.gate` over the module's existing channel-0 connection. The SDK's
//! session driver is private to its own transport; the wire bodies are shared.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use subc_client_rs::config::*;
use subc_protocol::{
    session::{HealthStatus, ModuleControlResponse},
    ErrorBody, Frame, FrameType,
};
use tokio::sync::{mpsc, Notify, Semaphore};

use super::{config_apply, config_review, LiveSettings, StartupSettings};
use crate::scope_watch::{ControlAnswer, ControlRequests};
use crate::{control_flags, ModuleError};

// Separate from scope queries, registration claims, and operator confirmation.
const FIRST_CONFIG_CORR: u64 = 1 << 56;
const CONTROL_DEADLINE: Duration = Duration::from_secs(5);

pub(crate) struct Session {
    requests: ControlRequests,
    changed: Notify,
    version: u8,
    health: Mutex<SettingsHealth>,
    reviews: Arc<Semaphore>,
}

enum SettingsHealth {
    Waiting(Option<String>),
    Refused(String),
    Applied,
}

impl Session {
    pub(crate) fn new(version: u8) -> Self {
        Self {
            requests: ControlRequests::starting_at(FIRST_CONFIG_CORR),
            changed: Notify::new(),
            version,
            health: Mutex::new(SettingsHealth::Waiting(None)),
            reviews: Arc::new(Semaphore::new(crate::DISPATCH_LOOKAHEAD_FRAMES)),
        }
    }

    fn set_health(&self, health: SettingsHealth) {
        *self
            .health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = health;
    }

    pub(crate) fn mark_applied(&self) {
        self.set_health(SettingsHealth::Applied);
    }

    pub(crate) fn annotate_health(&self, response: &mut ModuleControlResponse) {
        let health = self.health.try_lock().ok();
        let (reason, code) = match health.as_deref() {
            Some(SettingsHealth::Applied) => return,
            Some(SettingsHealth::Refused(code)) => ("settings_declaration_refused", Some(code)),
            Some(SettingsHealth::Waiting(code)) => ("settings_view_missing", code.as_ref()),
            None => ("settings_view_missing", None),
        };
        let reason = match code {
            Some(code) => format!("{reason}: {code}"),
            None => reason.to_owned(),
        };
        if let ModuleControlResponse::HealthCheck { status, detail, .. } = response {
            *status = HealthStatus::Degraded;
            *detail = Some(match detail.take() {
                Some(existing) => format!("{existing}; {reason}"),
                None => reason,
            });
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
        frame: &Frame,
        module_id: &str,
    ) -> Result<(), ModuleError> {
        let Ok(permit) = self.reviews.clone().try_acquire_owned() else {
            return crate::send_route_error(
                writer,
                self.version,
                0,
                0,
                frame.header.corr,
                "not_ready",
                "Cerebellum is already reviewing settings; retry later.",
            )
            .await;
        };
        // A schema review must not hold up health or delivery replies. The
        // worker uses a weak writer so reviews do not keep a closing connection alive.
        let writer = writer.downgrade();
        let version = self.version;
        let module_id = module_id.to_owned();
        let corr = frame.header.corr;
        let body = frame.body.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let (ty, body) = match serde_json::from_slice(&body) {
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
            };
            if let (Some(writer), Ok(body)) = (writer.upgrade(), body) {
                if let Ok(reply) =
                    Frame::build_with_version(version, ty, control_flags(), 0, 0, corr, body)
                {
                    let _ = writer.blocking_send(reply);
                }
            }
        });
        Ok(())
    }

    pub(crate) async fn initial(
        &self,
        writer: &mpsc::Sender<Frame>,
        declaration: ConfigDeclareRequest,
    ) -> Result<(StartupSettings, Option<ConfigAppliedRequest>), ()> {
        // Keep the original correlation until the daemon replies or the
        // connection ends; a slow response is not a refusal.
        match self
            .call::<serde_json::Value>(writer, &declaration, None)
            .await
        {
            Ok(_) => {}
            Err(Some(code)) => {
                self.set_health(SettingsHealth::Refused(code));
                return Err(());
            }
            Err(None) => self.changed.notified().await,
        }
        loop {
            match self.get(writer, None).await {
                Ok(reply) => {
                    self.set_health(SettingsHealth::Waiting(None));
                    let mut view = reply.pending.or_else(|| reply.active.clone());
                    while let Some(candidate) = view {
                        let startup = StartupSettings::from_view(&candidate);
                        let report = report(
                            &candidate,
                            startup.as_ref().map(|_| ()).map_err(Clone::clone),
                        );
                        if let Ok(startup) = startup {
                            return Ok((startup, report));
                        }
                        if let Some(report) = report {
                            let _ = self
                                .call::<serde_json::Value>(writer, &report, Some(CONTROL_DEADLINE))
                                .await;
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
                // A daemon can acknowledge config.declare before hashing the
                // declaration to build the config.get view. Gate decisions
                // such as config_gated do not permit bypassing managed settings.
                Err(Some(code)) if code == "value_invalid" => {
                    self.set_health(SettingsHealth::Refused(code));
                    return Err(());
                }
                Err(code) => self.set_health(SettingsHealth::Waiting(code)),
            }
            self.changed.notified().await;
        }
    }

    pub(crate) async fn live(
        &self,
        writer: &mpsc::Sender<Frame>,
        mut pending_report: Option<ConfigAppliedRequest>,
        apply: impl Fn(LiveSettings) + Clone + Send + 'static,
    ) {
        loop {
            let mut changed_while_reporting = false;
            if let Some(report) = pending_report.take() {
                while matches!(self.call::<serde_json::Value>(writer, &report, Some(CONTROL_DEADLINE)).await, Err(Some(code)) if code == "anchor_pending")
                {
                    self.changed.notified().await;
                    changed_while_reporting = true;
                }
            }
            if !changed_while_reporting {
                self.changed.notified().await;
            }
            let deadline = self.health.try_lock().ok().and_then(|health| {
                matches!(*health, SettingsHealth::Applied).then_some(CONTROL_DEADLINE)
            });
            let Ok(reply) = self.get(writer, deadline).await else {
                continue;
            };
            let Some(view) = reply.pending.or(reply.active) else {
                continue;
            };
            let result = match config_apply(&view) {
                Ok(settings) => {
                    // Replacing the legacy source can wait for an in-flight file
                    // read. Do not make the connection wait on that lock.
                    let apply = apply.clone();
                    tokio::task::spawn_blocking(move || apply(settings))
                        .await
                        .map_err(|error| error.to_string())
                }
                Err(error) => Err(error),
            };
            if result.is_ok() {
                self.mark_applied();
            }
            pending_report = report(&view, result);
        }
    }

    async fn get(
        &self,
        writer: &mpsc::Sender<Frame>,
        deadline: Option<Duration>,
    ) -> Result<ConfigGetReply, Option<String>> {
        let reply = self
            .call::<ConfigGetReply>(writer, &ConfigGetRequest::new(), deadline)
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
        deadline: Option<Duration>,
    ) -> Result<T, Option<String>> {
        match self
            .requests
            .request_with_version(writer, request, deadline, self.version)
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
