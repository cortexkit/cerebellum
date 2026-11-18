use super::*;
use cortexkit_test_support::ScratchDir;
use serde_json::{json, Map, Value};
use subc_protocol::{Frame, FrameType};
use subc_transport::connection_file::{self, ConnectionInfo, Endpoint, SCHEMA_VERSION};
use subc_transport::{authenticate_server, read_frame, write_frame};
use tokio::net::TcpListener;
use tokio::time::{sleep, timeout, timeout_at};

const IO_BUDGET: Duration = Duration::from_secs(3);

async fn never_answer_credential(
    listener: TcpListener,
    info: ConnectionInfo,
    attempts: mpsc::UnboundedSender<()>,
) {
    let mut unanswered = Vec::new();
    for _ in 0..2 {
        let (mut stream, _) = listener.accept().await.unwrap();
        authenticate_server(
            &mut stream,
            &info.key,
            &info.daemon_id,
            &info.daemon_ver,
            IO_BUDGET,
        )
        .await
        .unwrap();
        loop {
            let request = read_frame(&mut stream).await.unwrap().unwrap();
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(request.header.channel, 0);
            let reply = match body["op"].as_str() {
                Some("server.describe") => json!({
                    "op": "server.describe", "protocol_ver": 1, "subc_ops": [],
                    "capabilities": [], "connected_clients": 1,
                }),
                Some("route.open") => {
                    assert_eq!(body["target"]["module_id"], "ckbus");
                    json!({"op": "route.open", "route_channel": 7, "route_epoch": 1})
                }
                _ => panic!("unexpected control operation: {body}"),
            };
            let response = Frame::build(
                FrameType::Response,
                crate::control_flags(),
                0,
                0,
                request.header.corr,
                serde_json::to_vec(&reply).unwrap(),
            )
            .unwrap();
            write_frame(&mut stream, &response).await.unwrap();
            if body["op"] == "route.open" {
                break;
            }
        }
        let call = read_frame(&mut stream).await.unwrap().unwrap();
        assert_eq!((call.header.channel, call.header.epoch), (7, 1));
        assert_eq!(
            serde_json::from_slice::<Value>(&call.body).unwrap(),
            json!({"method": "ckbus.credential", "params": {}}),
        );
        // Keep the socket open: a lost response must time out, not read EOF.
        unanswered.push(stream);
        attempts.send(()).unwrap();
    }
    std::future::pending::<()>().await;
}

#[tokio::test]
async fn unanswered_ckbus_credential_times_out_and_retries() {
    let dir = ScratchDir::new("turn-hint-ckbus");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let path = dir.path().join("connection.json");
    let info = ConnectionInfo {
        schema: SCHEMA_VERSION,
        wire_version: None,
        endpoints: vec![Endpoint {
            host: "127.0.0.1".into(),
            port: listener.local_addr().unwrap().port(),
        }],
        key: vec![0x42; 32],
        daemon_id: [0x21; 16],
        pid: std::process::id(),
        daemon_ver: "0.49.0".into(),
    };
    connection_file::write_atomic(&path, &info).unwrap();
    let (observed, mut attempts) = mpsc::unbounded_channel();
    let daemon = tokio::spawn(never_answer_credential(listener, info, observed));

    let gauges = Arc::new(HintGauges::default());
    let (commands, task) = {
        let gauges = gauges.clone();
        let transport = Arc::new(LiveTransport::new(path, "cerebellum-turn-hint-test".into()));
        let (commands, receiver) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move { run(transport, receiver, |_| {}, &gauges).await });
        (commands, task)
    };
    let start = Instant::now();
    commands
        .send(Activity::Drawn("agent-a".into(), start + LINGER))
        .unwrap();
    assert_eq!(timeout(IO_BUDGET, attempts.recv()).await.unwrap(), Some(()));
    let metrics = timeout_at(start + Duration::from_millis(4_500), async {
        loop {
            let mut metrics = Map::new();
            gauges.insert_into(&mut metrics);
            if metrics["turnHintOpenFailures"] == 1 {
                break metrics;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect(
        "an unanswered ckbus.credential must count as an open failure within the open deadline",
    );
    assert_eq!(metrics["turnHintLastOpenFailureReason"], "timeout");
    assert_eq!(metrics["turnHintSubscriptionsOpened"], 0);
    assert_eq!(metrics["turnHintSubscriptionOpen"], false);
    assert_eq!(timeout(IO_BUDGET, attempts.recv()).await.unwrap(), Some(()));

    commands.send(Activity::Shutdown).unwrap();
    task.await.unwrap();
    daemon.abort();
    let _ = daemon.await;
}
