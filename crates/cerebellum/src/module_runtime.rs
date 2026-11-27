//! Register first, then wait for the settings that configure the execution
//! planes. Control traffic continues while settings or startup recovery run.

use std::collections::VecDeque;
use std::future::Future;

use subc_protocol::{
    config::{ConfigAppliedRequest, CONFIG_GATE_CAPABILITY},
    session::HealthStatus,
};
use tokio::task::JoinHandle;

use super::*;
use crate::settings::{LiveSettings, Session, StartupSettings};

const STARTUP_WAIT: Duration = Duration::from_secs(5);

pub(super) struct Prepared {
    pub(super) planes: Planes,
    pub(super) teardown: ShutdownTeardown,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(super) _user_browser_listener: Option<user_browser_bridge::BridgeListener>,
}

type Preparation = (ModuleConfig, Prepared, Option<ConfigAppliedRequest>);

pub(super) async fn run(
    config: ModuleConfig,
    prepare: impl FnOnce(&mut Planes) + Send + 'static,
    real_module: bool,
    registration: Option<registration::Stream>,
) -> ModuleEnding {
    // A SIGTERM arriving during connection or startup is held until the
    // module can act on it and join any recovery work it already started.
    #[cfg(unix)]
    let mut sigterm = listen_for_sigterm();
    let stream = match connect_to_subc(&config.connection_file_path, registration).await {
        Ok(stream) => stream,
        Err(error) => return ModuleEnding::Disconnected(Err(error)),
    };
    let (mut read_half, write_half) = tokio::io::split(stream);
    let deadlines = Arc::new(ConnectionDeadlines::default());
    let mut preparing: Option<JoinHandle<Preparation>> = None;
    let mut ready: Option<Prepared> = None;
    let preparing_slot = &mut preparing;
    let ready_slot = &mut ready;
    let serving = drive_connection(write_half, deadlines.clone(), |writer| async move {
        let declaration = real_module
            .then(cerebellum_core::config::config_path)
            .flatten()
            .as_deref()
            .and_then(settings::config_declaration);
        let can_declare = declaration.is_some();
        send_hello(&writer, &config, real_module, can_declare).await?;
        let ack = expect_hello_ack(&mut read_half).await?;
        let managed = can_declare
            && ack
                .subc_capabilities
                .iter()
                .any(|cap| cap == CONFIG_GATE_CAPABILITY);
        let session = real_module.then(|| Session::new(ack.negotiated_ver));
        let mut incoming = Incoming::new(&mut read_half, read_one);
        let mut waiting = VecDeque::new();
        let module_id = config.module_id.clone();
        let startup = async {
            let (startup, report) = match (&session, declaration.filter(|_| managed)) {
                (Some(session), Some(declaration)) => {
                    let (settings, report) = session.initial(&writer, declaration).await;
                    (Some(settings), report)
                }
                (Some(_), None) => std::future::pending().await,
                (None, _) => (None, None),
            };
            let output = preparing_slot
                .insert(tokio::task::spawn_blocking(move || {
                    let mut config = config;
                    let mut live = LiveSettings::default();
                    #[cfg(target_os = "linux")]
                    let mut applied_browser = None;
                    if let Some(startup) = startup {
                        #[cfg(target_os = "linux")]
                        let startup = {
                            let mut startup = startup;
                            applied_browser = Some(startup.validate_browser());
                            startup
                        };
                        let StartupSettings {
                            health,
                            agent_cursor,
                            browser,
                            live: effective,
                            ..
                        } = startup;
                        config.health = health;
                        config.agent_cursor = agent_cursor;
                        config.browser = browser;
                        live = effective;
                    }
                    let mut prepared = prepare_module(&config, prepare, real_module);
                    deadlines.install_display(Arc::clone(&prepared.planes.routes.display));
                    prepared.planes.egress_deadlines = deadlines;
                    if real_module {
                        prepared.planes.runtime_browser = Some(config.browser.clone());
                        apply_live(&prepared.planes, live);
                        #[cfg(target_os = "linux")]
                        if let Some(applied) = applied_browser {
                            applied.record();
                        }
                    }
                    (config, prepared, report)
                }))
                .await;
            preparing_slot.take();
            let output = output.map_err(|error| ModuleError::Message(error.to_string()))?;
            if let Some(session) = &session {
                session.mark_applied();
            }
            Ok(output)
        };
        let result = wait_for_startup(
            &mut incoming,
            &writer,
            session.as_ref(),
            &module_id,
            &mut waiting,
            startup,
        )
        .await;
        let Some((config, prepared, report)) = result? else {
            return Ok(());
        };
        let planes = prepared.planes.clone();
        *ready_slot = Some(prepared);
        let _consent_shutdown = ConsentShutdown(Arc::clone(&planes.drain_signal));
        let serve = Box::pin(serve_registered(
            incoming,
            waiting,
            writer.clone(),
            &config,
            planes.clone(),
            session.as_ref(),
        ));
        if let Some(session) = &session {
            tokio::select! {
                result = serve => result,
                () = session.live(&writer, report, move |settings| apply_live(&planes, settings)) => unreachable!("settings live loop ends with the connection"),
            }
        } else {
            serve.await
        }
    });
    #[cfg(unix)]
    let ending = end_on_disconnect_or_sigterm(serving, sigterm.as_mut()).await;
    #[cfg(not(unix))]
    let ending = ModuleEnding::Disconnected(serving.await);

    // A blocking startup worker cannot be cancelled mid-recovery. Join it if
    // the connection ended or SIGTERM arrived before it could publish planes.
    let cleanup = async {
        if let Some(worker) = preparing.take() {
            if let Ok((_, prepared, _)) = worker.await {
                ready = Some(prepared);
            }
        }
        if let Some(prepared) = ready {
            prepared.teardown.run_or_join().await;
        }
    };
    #[cfg(unix)]
    let mut cleanup = std::pin::pin!(cleanup);
    #[cfg(unix)]
    if let (ModuleEnding::Disconnected(_), Some(sigterm)) = (&ending, sigterm.as_mut()) {
        // EOF may have started teardown before SIGTERM arrived. Join the same
        // cleanup in either case, but let the signal decide how the process exits.
        return tokio::select! {
            biased;
            Some(()) = sigterm.recv() => {
                cleanup.await;
                ModuleEnding::Terminated
            }
            () = &mut cleanup => ending,
        };
    }
    cleanup.await;
    ending
}

async fn wait_for_startup<R, F, Next, T>(
    incoming: &mut Incoming<F, Next>,
    writer: &mpsc::Sender<Frame>,
    session: Option<&Session>,
    module_id: &str,
    waiting: &mut VecDeque<Frame>,
    work: impl Future<Output = Result<T, ModuleError>>,
) -> Result<Option<T>, ModuleError>
where
    F: Future<Output = (Result<Option<Frame>, String>, R)>,
    Next: Fn(R) -> F,
{
    let mut work = std::pin::pin!(work);
    let mut timeout = std::pin::pin!(tokio::time::sleep(STARTUP_WAIT));
    let health = HealthState::new();
    let mut expired = false;
    loop {
        tokio::select! {
            biased;
            result = &mut work => return result.map(Some),
            () = &mut timeout, if !expired => {
                expired = true;
                for frame in waiting.drain(..) {
                    refuse_early(frame, writer, session.is_some()).await?;
                }
            }
            incoming = incoming.read() => {
                let Some(frame) = incoming.map_err(ModuleError::Message)? else { return Ok(None) };
                if control::is_health_request(&frame) {
                    let mut report = health.report();
                    if let Some(session) = session {
                        session.annotate_health(&mut report);
                    } else if let ModuleControlResponse::HealthCheck { status, detail, .. } = &mut report {
                        *status = HealthStatus::Degraded;
                        *detail = Some("startup_in_progress".into());
                    }
                    control::send_control_response(&frame, writer, report).await?;
                    continue;
                }
                if session.is_some_and(|session| session.take(&frame)) { continue; }
                if let Some(session) = session.filter(|session| session.is_review(&frame)) {
                    session.review(writer, &frame, module_id).await?;
                    continue;
                }
                if frame.header.channel == 0 {
                    if frame.header.ty == FrameType::Goodbye || is_draining(&frame) { return Ok(None); }
                    if frame.header.ty == FrameType::Ping {
                        let reply = Frame::build_with_version(frame.header.ver, FrameType::Pong, frame.header.flags, 0, 0, frame.header.corr, Vec::new())
                            .map_err(|error| ModuleError::Message(error.to_string()))?;
                        send(writer, reply).await?;
                        continue;
                    }
                }
                if !expired && waiting.len() == DISPATCH_LOOKAHEAD_FRAMES {
                    // Do not keep any early work if we cannot also keep its
                    // later cancels and route-close messages in arrival order.
                    expired = true;
                    for queued in waiting.drain(..) {
                        refuse_early(queued, writer, session.is_some()).await?;
                    }
                }
                if expired {
                    refuse_early(frame, writer, session.is_some()).await?;
                } else {
                    waiting.push_back(frame);
                }
            }
        }
    }
}

fn is_draining(frame: &Frame) -> bool {
    frame.header.ty == FrameType::Push
        && matches!(
            serde_json::from_slice(&frame.body),
            Ok(subc_protocol::session::ModuleControlCommand::Draining { .. })
        )
}

async fn refuse_early(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    waiting_for_settings: bool,
) -> Result<(), ModuleError> {
    if frame.header.ty != FrameType::Request {
        return Ok(());
    }
    let header = frame.header;
    send_route_error(
        writer,
        header.ver,
        header.channel,
        header.epoch,
        header.corr,
        "not_ready",
        if waiting_for_settings {
            "Cerebellum is waiting for managed settings; check `ck config status` before retrying."
        } else {
            "Cerebellum is still initializing; retry this request later."
        },
    )
    .await
}

pub(super) async fn offer_settings_control(
    session: &Session,
    frame: &Frame,
    writer: &mpsc::Sender<Frame>,
    module_id: &str,
    planes: &Planes,
) -> Result<bool, ModuleError> {
    if session.take(frame) {
        return Ok(true);
    }
    if control::is_health_request(frame) {
        let mut report = control::health_report(
            &planes.health,
            &planes.routes,
            Some(&planes.call_record_workers),
            Some(&planes.private_content),
        );
        session.annotate_health(&mut report);
        control::send_control_response(frame, writer, report).await?;
        return Ok(true);
    }
    if session.is_review(frame) {
        session.review(writer, frame, module_id).await?;
        return Ok(true);
    }
    Ok(false)
}

fn apply_live(planes: &Planes, settings: LiveSettings) {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    if let Ok(computer) = &planes.computer {
        computer.apply_live_settings(settings);
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let _ = (planes, settings);
}

#[cfg(test)]
#[path = "module_runtime_tests.rs"]
mod settings_tests;
