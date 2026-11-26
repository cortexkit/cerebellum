//! Explicit live desk probe; never invoked by tests or the Rust gate.
//!
//! Run only with the operator's approval: `cargo run -p cerebellum --example open_app_live`.
//! Running this probe approves one Calculator launch through the normal app
//! consent relay. It uses an isolated journal and never activates or quits it.
//! The responsible pid must equal Calculator's pid, not this probe's pid.

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("Calculator launch probe requires macOS");
}

#[cfg(target_os = "macos")]
#[tokio::main]
async fn main() {
    use cerebellum::{JournalPersistence, Planes};
    use serde_json::json;
    use std::sync::Arc;
    use subc_protocol::{Flags, Frame, FrameType, Priority, PROTOCOL_VERSION};
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(cerebellum_core::health::HealthState::default()),
        None,
        JournalPersistence::Isolated,
    );
    // This explicit probe exercises the implementation even in a development
    // build without release review identifiers. It does not change advertisement.
    planes.computer_admitted = Arc::new(["computer.open_app".to_string()].into());
    let opening = Frame::build_with_version(PROTOCOL_VERSION,FrameType::Request,Flags::new(false,Priority::Interactive,false),9,3,71,serde_json::to_vec(&json!({"name":"computer_use","arguments":{"action":"open_app","target":"com.apple.calculator"}})).unwrap()).unwrap();
    // Bind an explicit local route that can relay the app consent question.
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let bind = subc_protocol::session::ModuleControlRequest::RouteBind {
        role_versions: None,
        call_mode: None,
        route_channel: 9,
        epoch: 3,
        target: subc_protocol::RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
        identity: subc_protocol::BindIdentity::new("desk", "open-app-live"),
        principal: cerebellum::session_caller_principal_for_test(),
        consumer_capabilities: Some(vec!["elicitation".into()]),
        admission_facts: Some(
            json!({"agentProjectId":"open-app-live","sessionKind":"primary","effectiveCapabilityScope":["*"]}),
        ),
        scope: None,
    };
    let control = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Passive, false),
        0,
        0,
        1,
        serde_json::to_vec(&bind).unwrap(),
    )
    .unwrap();
    cerebellum::handle_frame_for_test(control, &tx, &planes)
        .await
        .unwrap();
    let admitted = rx.recv().await.expect("route admission reply");
    assert_eq!(
        admitted.header.ty,
        FrameType::Response,
        "{}",
        String::from_utf8_lossy(&admitted.body)
    );
    cerebellum::handle_frame_for_test(opening, &tx, &planes)
        .await
        .unwrap();
    loop {
        let frame = rx.recv().await.expect("launch reply");
        if frame.header.ty == FrameType::Request {
            let answer = Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Response,
                Flags::new(false, Priority::Interactive, false),
                frame.header.channel,
                frame.header.epoch,
                frame.header.corr,
                serde_json::to_vec(&json!({"decision":"allow_30m"})).unwrap(),
            )
            .unwrap();
            cerebellum::handle_frame_for_test(answer, &tx, &planes)
                .await
                .unwrap();
        } else {
            let reply: serde_json::Value = serde_json::from_slice(&frame.body).unwrap();
            println!("{reply}");
            if let Some(pid) = reply["pid"]
                .as_u64()
                .and_then(|pid| u32::try_from(pid).ok())
            {
                let responsible = cerebellum_macos::responsible_pid(pid);
                println!(
                    "pid={pid} responsible_pid={responsible:?} frontmost={} has_window={}",
                    reply["frontmost"], reply["has_window"]
                );
                assert_eq!(
                    responsible,
                    Some(pid),
                    "launch inherited the probe's responsibility"
                );
            } else {
                std::process::exit(2);
            }
            break;
        }
    }
}
