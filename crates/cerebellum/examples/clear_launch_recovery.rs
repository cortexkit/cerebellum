//! Clear a browser launch record that startup recovery kept, through the
//! production management operation and its consent question.
//!
//! When a module start cannot prove that a browser from before the restart is
//! gone, it keeps that launch record active and holds the project's profile, so
//! every launch on it answers `profile_recovery_pending`. For a record with no
//! attestation the module trusts, no later start can change that.
//! `browser.clear_launch_recovery` is the way out: it reads that no running
//! process names the profile directory and that Chrome's `SingletonLock` names
//! no running browser, asks a person, reads both again, and only then consumes
//! the record and releases the profile.
//!
//! The kept set lives in the memory of the process whose startup recovery
//! built it, so this tool runs that recovery itself, against the live launch
//! journal and profile root, exactly as a module start does. Run it only while
//! the cerebellum module is stopped: two recoveries over one journal would
//! contend for the same records.
//!
//! By default it answers KEEP, which changes nothing and shows what a clear
//! would do. Pass `--allow` only after the operator has approved the clear;
//! the approval should be recorded somewhere they can see.
//!
//! Run: `cargo run -p cerebellum --example clear_launch_recovery -- <agent_project_id> <browser-config-path> [--allow]`

#[cfg(target_os = "macos")]
mod live {
    use std::path::Path;
    use std::process::ExitCode;
    use std::sync::Arc;
    use std::time::Duration;

    use cerebellum::browser_launch_service::ProductionLaunchService;
    use cerebellum::management::{ManagementPlane, TargetResolver, CLEAR_LAUNCH_RECOVERY};
    use cerebellum::{HealthState, JournalPersistence, Planes};
    use cerebellum_computer::platform::TargetResolution;
    use serde_json::{json, Value};
    use subc_protocol::session::ModuleControlRequest;
    use subc_protocol::{
        BindIdentity, Flags, Frame, FrameType, Principal, Priority, RouteTarget, PROTOCOL_VERSION,
    };
    use tokio::sync::mpsc;

    const CHANNEL: u16 = 4;
    const EPOCH: u32 = 1;

    /// Clearing opens no application, so nothing is ever resolved.
    struct NoTargets;

    impl TargetResolver for NoTargets {
        fn resolve(&self, _bundle_identity: &str) -> TargetResolution {
            TargetResolution::NotRunning
        }
    }

    fn frame(ty: FrameType, channel: u16, epoch: u32, corr: u64, body: &Value) -> Frame {
        Frame::build_with_version(
            PROTOCOL_VERSION,
            ty,
            Flags::new(false, Priority::Interactive, false),
            channel,
            epoch,
            corr,
            serde_json::to_vec(body).expect("serialize"),
        )
        .expect("frame")
    }

    pub async fn run(project: String, config_path: &Path, allow: bool) -> ExitCode {
        let text = match std::fs::read_to_string(config_path) {
            Ok(text) => text,
            Err(error) => {
                eprintln!("cannot read the supplied browser configuration: {error}");
                return ExitCode::from(1);
            }
        };
        let config = match cerebellum::browser_config::parse_browser_config(&text) {
            Ok(Some(config)) => config,
            Ok(None) => {
                eprintln!("no browser is configured, so there is no launch journal to clear");
                return ExitCode::from(1);
            }
            Err(error) => {
                eprintln!("the browser configuration did not load: {error:?}");
                return ExitCode::from(1);
            }
        };
        let management = Arc::new(ManagementPlane::new(Arc::new(NoTargets)));
        // Startup recovery over the live journal and profile root, publishing
        // what it kept into this plane. Kept alive until the tool exits: the
        // clear releases custody this service's recovery holds.
        let _service = ProductionLaunchService::open_publishing(
            config,
            JournalPersistence::Durable,
            &management.launch_recovery_registry(),
        );
        let mut planes = Planes::with_browser_config_journaling(
            Arc::new(HealthState::default()),
            None,
            // The clear writes the launch journal and profile custody; the
            // audit journal has nothing to say about it, so keep it off disk.
            JournalPersistence::Isolated,
        );
        planes.management = management;

        let bind = ModuleControlRequest::RouteBind {
            role_versions: None,
            call_mode: None,
            route_channel: CHANNEL,
            epoch: EPOCH,
            target: RouteTarget::ManagementSurface {
                module_id: "cerebellum".to_string(),
            },
            identity: BindIdentity::new("operator".to_string(), "operator-desk".to_string()),
            principal: Some(Principal::Direct),
            consumer_capabilities: Some(vec!["elicitation".to_string()]),
            admission_facts: None,
            scope: None,
        };
        let (bind_writer, mut bind_replies) = mpsc::channel(2);
        let bind_frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            0,
            0,
            u64::from(CHANNEL),
            serde_json::to_vec(&bind).expect("serialize bind"),
        )
        .expect("bind frame");
        if let Err(error) = cerebellum::handle_control_request_for_test_with_bindings(
            bind_frame,
            &bind_writer,
            &planes.health,
            &planes.routes,
        )
        .await
        {
            eprintln!("route.bind failed: {error:?}");
            return ExitCode::from(1);
        }
        let _ = bind_replies.recv().await;

        let (writer, mut frames) = mpsc::channel(8);
        let request = |corr: u64| {
            frame(
                FrameType::Request,
                CHANNEL,
                EPOCH,
                corr,
                &json!({"method": CLEAR_LAUNCH_RECOVERY, "params": {"agent_project_id": project}}),
            )
        };
        if let Err(error) = cerebellum::handle_frame_for_test(request(10), &writer, &planes).await {
            eprintln!("clear request failed: {error:?}");
            return ExitCode::from(1);
        }

        let mut reply = None;
        let mut question = None;
        while reply.is_none() || (question.is_none() && reply_is_pending(reply.as_ref())) {
            let Ok(Some(received)) =
                tokio::time::timeout(Duration::from_secs(10), frames.recv()).await
            else {
                eprintln!("no reply or question within 10 s");
                return ExitCode::from(1);
            };
            let body: Value = serde_json::from_slice(&received.body).unwrap_or(Value::Null);
            if received.header.ty == FrameType::Request {
                question = Some((received, body));
            } else {
                reply = Some(body);
            }
        }
        let reply = reply.unwrap_or(Value::Null);
        println!("reply: {reply}");
        let Some((question_frame, question_body)) = question else {
            // Nothing kept, or a refusal: the reply says which.
            return ExitCode::from(if reply["outcome"] == "consent_pending" {
                1
            } else {
                0
            });
        };
        println!(
            "question: {}",
            serde_json::to_string_pretty(&question_body["params"]).unwrap_or_default()
        );

        let decision = if allow { "clear" } else { "keep" };
        println!("answering: {decision}");
        let answer = frame(
            FrameType::Response,
            question_frame.header.channel,
            question_frame.header.epoch,
            question_frame.header.corr,
            &json!({"decision": decision}),
        );
        if let Err(error) = cerebellum::handle_frame_for_test(answer, &writer, &planes).await {
            eprintln!("answer failed: {error:?}");
            return ExitCode::from(1);
        }
        let settled = tokio::time::timeout(Duration::from_secs(30), async {
            while planes
                .management
                .launch_recovery_clear_pending_count()
                .await
                != 0
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        if settled.is_err() {
            eprintln!("the clear did not settle within 30 s");
            return ExitCode::from(1);
        }

        // Ask again: the reply carries what the answer did.
        if let Err(error) = cerebellum::handle_frame_for_test(request(11), &writer, &planes).await {
            eprintln!("follow-up request failed: {error:?}");
            return ExitCode::from(1);
        }
        while let Ok(Some(received)) =
            tokio::time::timeout(Duration::from_secs(10), frames.recv()).await
        {
            if received.header.ty != FrameType::Request {
                let body: Value = serde_json::from_slice(&received.body).unwrap_or(Value::Null);
                println!("answer did: {}", body["previous_answer"]);
                return ExitCode::SUCCESS;
            }
        }
        eprintln!("no follow-up reply within 10 s");
        ExitCode::from(1)
    }

    fn reply_is_pending(reply: Option<&Value>) -> bool {
        reply.is_some_and(|reply| reply["outcome"] == "consent_pending")
    }
}

#[cfg(target_os = "macos")]
#[tokio::main]
async fn main() -> std::process::ExitCode {
    let mut project = None;
    let mut config = None;
    let mut allow = false;
    for argument in std::env::args().skip(1) {
        if argument == "--allow" {
            allow = true;
        } else if project.is_none() {
            project = Some(argument);
        } else if config.is_none() {
            config = Some(argument);
        } else {
            eprintln!("unexpected argument: {argument}");
            return std::process::ExitCode::from(2);
        }
    }
    let (Some(project), Some(config)) = (project, config) else {
        eprintln!(
            "usage: clear_launch_recovery <agent_project_id> <browser-config-path> [--allow]"
        );
        return std::process::ExitCode::from(2);
    };
    live::run(project, std::path::Path::new(&config), allow).await
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("clear_launch_recovery drives the desk launch journal and runs on macOS only");
}
