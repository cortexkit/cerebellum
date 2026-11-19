//! A frame handler that waits for the daemon's answer to a control request gets
//! it while the handler is still running.
//!
//! The daemon sends that answer on the module connection, the same connection
//! whose frames the dispatch loop hands to handlers one at a time. These tests
//! run the whole connection (`run_connection`) against a scripted daemon.

use super::*;
use crate::scope_watch::ControlAnswer;
use crate::test_support::HANG_GUARD;
use subc_transport::{read_frame, write_frame};

/// A display catalog whose read asks the daemon one control question on the
/// module connection, the way a claim mint does on a channel launch, and
/// records the answer it got (`None` when the question went unanswered).
struct AskingDisplay {
    scopes: Arc<scope_watch::ScopeRevocation>,
    answers: Arc<std::sync::Mutex<Vec<Option<ControlAnswer>>>>,
}

impl tool_display::Backend for AskingDisplay {
    fn declarers(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<Vec<String>>> + Send + '_>> {
        Box::pin(async move {
            let answer = self
                .scopes
                .control
                .request_connected(&json!({"op":"test.question"}), Duration::from_secs(2))
                .await;
            self.answers.lock().unwrap().push(answer);
            // The binding principal is the one display module, so the bind is
            // admitted as a view reader whatever the answer was.
            Some(vec!["display-reader".into()])
        })
    }
}

fn control_frame(ty: FrameType, corr: u64, body: Value) -> Frame {
    Frame::build(
        ty,
        control_flags(),
        0,
        0,
        corr,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap()
}

/// A bind the module must check against the display catalog: a reserved
/// principal binding to cerebellum's tools may be a display module reading views.
fn view_reader_bind(corr: u64) -> Frame {
    control_frame(
        FrameType::Request,
        corr,
        json!({"op":"route.bind", "route_channel":9, "epoch":1,
            "principal":subc_protocol::Principal::Reserved { module_id: "display-reader".into() },
            "identity":subc_protocol::BindIdentity::new("test", "display"),
            "target":subc_protocol::RouteTarget::ToolProvider { module_id: "cerebellum".into() }}),
    )
}

async fn next(peer: &mut tokio::io::DuplexStream) -> Frame {
    tokio::time::timeout(HANG_GUARD, read_frame(peer))
        .await
        .expect("the module writes a frame")
        .unwrap()
        .expect("module connection open")
}

#[tokio::test]
async fn a_bind_awaiting_a_control_answer_gets_it_while_a_later_request_waits_its_turn() {
    let planes = crate::tests::management_bound_planes(1, 1);
    let answers = Arc::new(std::sync::Mutex::new(Vec::new()));
    planes.routes.display.connect(Arc::new(AskingDisplay {
        scopes: Arc::clone(&planes.scopes),
        answers: Arc::clone(&answers),
    }));
    let config = ModuleConfig {
        connection_file_path: PathBuf::new(),
        module_id: "cerebellum".into(),
        health: HealthConfig::DEFAULT,
        agent_cursor: false,
        browser: BrowserSurface::NotConfigured,
    };
    let (module_side, mut peer) = tokio::io::duplex(1 << 20);
    let (mut reader, writer) = tokio::io::split(module_side);

    let daemon = async move {
        let hello = next(&mut peer).await;
        assert_eq!(hello.header.ty, FrameType::Hello);
        write_frame(
            &mut peer,
            &control_frame(
                FrameType::HelloAck,
                HELLO_CORR,
                json!({"negotiated_ver":PROTOCOL_VERSION,"subc_ops":[],"subc_capabilities":[]}),
            ),
        )
        .await
        .unwrap();
        write_frame(&mut peer, &view_reader_bind(10)).await.unwrap();
        // The bind's catalog read asks its question before the bind is answered.
        let question = loop {
            let frame = next(&mut peer).await;
            let body: Value = serde_json::from_slice(&frame.body).unwrap_or_default();
            if (frame.header.ty, frame.header.channel) == (FrameType::Request, 0)
                && body["op"] == "test.question"
            {
                break frame;
            }
        };
        // A later request arrives ahead of the answer, as a health probe or
        // another agent's bind does on a busy connection.
        write_frame(
            &mut peer,
            &control_frame(FrameType::Request, 11, json!({"op":"health.check"})),
        )
        .await
        .unwrap();
        write_frame(
            &mut peer,
            &control_frame(
                FrameType::Response,
                question.header.corr,
                json!({"op":"test.question", "answered":true}),
            ),
        )
        .await
        .unwrap();
        // The bind is answered first, then the request that arrived after it.
        let mut order = Vec::new();
        while order.len() < 2 {
            let frame = next(&mut peer).await;
            if frame.header.channel == 0 && matches!(frame.header.corr, 10 | 11) {
                assert_eq!(
                    frame.header.ty,
                    FrameType::Response,
                    "{}",
                    String::from_utf8_lossy(&frame.body)
                );
                order.push(frame.header.corr);
            }
        }
        assert_eq!(order, [10, 11]);
        // Closing the connection ends the module's loop.
    };
    let (ended, ()) = tokio::join!(run_connection(&mut reader, writer, &config, planes), daemon);
    assert!(ended.is_ok(), "{ended:?}");
    assert_eq!(
        *answers.lock().unwrap(),
        [Some(ControlAnswer::Response(
            json!({"op":"test.question", "answered":true})
        ))],
        "the bind's catalog read never received the daemon's answer"
    );
}

#[tokio::test]
async fn an_answer_nobody_awaits_waits_its_turn_and_is_dropped() {
    let planes = crate::tests::management_bound_planes(1, 1);
    let config = ModuleConfig {
        connection_file_path: PathBuf::new(),
        module_id: "cerebellum".into(),
        health: HealthConfig::DEFAULT,
        agent_cursor: false,
        browser: BrowserSurface::NotConfigured,
    };
    let (module_side, mut peer) = tokio::io::duplex(1 << 20);
    let (mut reader, writer) = tokio::io::split(module_side);
    let daemon = async move {
        assert_eq!(next(&mut peer).await.header.ty, FrameType::Hello);
        write_frame(
            &mut peer,
            &control_frame(
                FrameType::HelloAck,
                HELLO_CORR,
                json!({"negotiated_ver":PROTOCOL_VERSION,"subc_ops":[],"subc_capabilities":[]}),
            ),
        )
        .await
        .unwrap();
        // A stray answer between two requests is neither answered nor allowed to
        // disturb the order of the requests around it.
        for frame in [
            control_frame(FrameType::Request, 20, json!({"op":"health.check"})),
            control_frame(FrameType::Response, 1 << 48, json!({"op":"claim.mint"})),
            control_frame(FrameType::Request, 21, json!({"op":"health.check"})),
        ] {
            write_frame(&mut peer, &frame).await.unwrap();
        }
        let mut order = Vec::new();
        while order.len() < 2 {
            let frame = next(&mut peer).await;
            if frame.header.channel == 0 {
                assert_eq!(frame.header.ty, FrameType::Response);
                order.push(frame.header.corr);
            }
        }
        assert_eq!(order, [20, 21]);
    };
    let (ended, ()) = tokio::join!(run_connection(&mut reader, writer, &config, planes), daemon);
    assert!(ended.is_ok(), "{ended:?}");
}
