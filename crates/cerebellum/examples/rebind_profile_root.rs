//! Rebind the operator's LIVE browser profile root, through the production
//! management operation and its consent question.
//!
//! The registry pins its managed root by stored facts (path, inode, birth time).
//! When those stop matching (a restore, a replaced directory, or a registry
//! written before the fact-based identity existed), every launch refuses until
//! `browser.rebind_profile_root` re-identifies the root. That operation asks a
//! person first and names the facts it will change. This tool runs it in
//! process against the live data home and prints the question, so the operator
//! reads exactly what the elicitation would show.
//!
//! By default it answers DENY, which writes nothing. That shows what a rebind
//! would do. Pass `--allow` only after the operator has approved the rebind;
//! the approval should be recorded somewhere they can see.
//!
//! Run: `cargo run -p cerebellum --example rebind_profile_root [-- --allow]`

#[cfg(target_os = "macos")]
mod live {
    use std::path::PathBuf;
    use std::process::ExitCode;
    use std::sync::Arc;
    use std::time::Duration;

    use cerebellum::browser_launch_service::production_profile_lifecycle;
    use cerebellum::management::{ManagementPlane, TargetResolver, REBIND_PROFILE_ROOT};
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

    /// Rebinding opens no application, so nothing is ever resolved.
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

    pub async fn run(allow: bool) -> ExitCode {
        let lifecycle = match production_profile_lifecycle() {
            Ok(lifecycle) => Arc::new(lifecycle),
            Err(error) => {
                eprintln!("the live registry did not open: {error:?}");
                return ExitCode::from(1);
            }
        };
        println!(
            "root: {}",
            lifecycle.registry().root().canonical_path().display()
        );
        let mut planes = Planes::with_browser_config_journaling(
            Arc::new(HealthState::default()),
            None,
            // A rebind writes the registry and its own append-only record; the
            // audit journal has nothing to say about it, so keep it off disk.
            JournalPersistence::Isolated,
        );
        planes.management = Arc::new(ManagementPlane::with_profile_lifecycle(
            Arc::new(NoTargets),
            lifecycle,
        ));

        let bind = ModuleControlRequest::RouteBind {
            route_channel: CHANNEL,
            epoch: EPOCH,
            target: RouteTarget::ManagementSurface {
                module_id: "cerebellum".to_string(),
            },
            identity: BindIdentity::new(
                PathBuf::from("/operator-desk"),
                "operator".to_string(),
                "operator-desk".to_string(),
            ),
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
        let request = frame(
            FrameType::Request,
            CHANNEL,
            EPOCH,
            10,
            &json!({"method": REBIND_PROFILE_ROOT, "params": {}}),
        );
        if let Err(error) = cerebellum::handle_frame_for_test(request, &writer, &planes).await {
            eprintln!("rebind request failed: {error:?}");
            return ExitCode::from(1);
        }

        let mut reply = None;
        let mut question = None;
        while reply.is_none() || (question.is_none() && reply_is_pending(reply.as_ref())) {
            let Ok(Some(received)) =
                tokio::time::timeout(Duration::from_secs(5), frames.recv()).await
            else {
                eprintln!("no reply or question within 5 s");
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
            // Nothing to rebind (already bound) or a refusal: the reply says which.
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

        let decision = if allow { "allow" } else { "deny" };
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
        let settled = tokio::time::timeout(Duration::from_secs(10), async {
            while planes.management.profile_root_rebind_pending_count().await != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        if settled.is_err() {
            eprintln!("the rebind did not settle within 10 s");
            return ExitCode::from(1);
        }
        println!("settled");
        ExitCode::SUCCESS
    }

    fn reply_is_pending(reply: Option<&Value>) -> bool {
        reply.is_some_and(|reply| reply["outcome"] == "consent_pending")
    }
}

#[cfg(target_os = "macos")]
#[tokio::main]
async fn main() -> std::process::ExitCode {
    let allow = std::env::args().any(|argument| argument == "--allow");
    live::run(allow).await
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("rebind_profile_root drives the desk registry and runs on macOS only");
}
