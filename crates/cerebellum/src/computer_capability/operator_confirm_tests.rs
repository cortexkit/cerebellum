use super::*;
use serde_json::json;

#[test]
fn only_a_typed_confirmed_reply_approves_and_every_error_fails_closed() {
    let frame = |kind, body| {
        Frame::build(
            kind,
            crate::control_flags(),
            0,
            0,
            1,
            serde_json::to_vec(&body).unwrap(),
        )
        .unwrap()
    };
    assert_eq!(
        decode(&frame(
            FrameType::Response,
            json!({"op":"operator.confirm","outcome":"confirmed"})
        )),
        Ok(())
    );
    for body in [
        json!({"outcome":"confirmed"}),
        json!({"op":"operator.confirm","outcome":"ok"}),
        json!(null),
    ] {
        assert_eq!(
            decode(&frame(FrameType::Response, body)),
            Err(Failure::PresenceUnavailable)
        );
    }
    for (code, detail, expected) in [
        ("operator_declined", json!(null), Failure::Declined),
        (
            "operator_declined",
            json!({"reason":"backoff","retry_after_ms":1234}),
            Failure::Backoff {
                retry_after_ms: 1234,
            },
        ),
        (
            "operator_presence_unavailable",
            json!({"reason":"screen_locked"}),
            Failure::PresenceUnavailable,
        ),
        (
            "operator_summary_invalid",
            json!(null),
            Failure::SummaryInvalid,
        ),
        (
            "operator_request_not_permitted",
            json!(null),
            Failure::NotPermitted,
        ),
        ("not_registered", json!(null), Failure::NotPermitted),
        (
            "unsupported_control_frame",
            json!(null),
            Failure::Unsupported,
        ),
        ("future_error", json!(null), Failure::PresenceUnavailable),
    ] {
        assert_eq!(
            decode(&frame(
                FrameType::Error,
                json!({"code":code,"message":"refused","detail":detail})
            )),
            Err(expected)
        );
    }
}

#[tokio::test]
async fn dropping_a_sent_request_withdraws_even_when_the_egress_queue_is_full() {
    let wire = Arc::new(Wire::default());
    let (writer, mut receiver) = mpsc::channel(2);
    let request = {
        let waiting = wire.request(&writer, (7, 9));
        tokio::pin!(waiting);
        let request = tokio::select! {
            _ = &mut waiting => panic!("request should wait for the daemon"),
            frame = receiver.recv() => frame.unwrap(),
        };
        let body: OperatorConfirmRequest = serde_json::from_slice(&request.body).unwrap();
        assert_eq!((body.route_channel, body.route_epoch), (7, 9));
        assert_eq!(request.header.channel, 0);
        // One reserved slot is held for withdrawal, leaving only one ordinary slot.
        writer.try_send(request.clone()).unwrap();
        request
    };
    assert_eq!(receiver.recv().await.unwrap().header.ty, FrameType::Request);
    let cancel = receiver.recv().await.unwrap();
    assert_eq!(cancel.header.ty, FrameType::Cancel);
    assert_eq!(cancel.header.corr, request.header.corr);
    assert!(wire.pending.lock().unwrap().is_empty());
    assert!(!wire.deliver(&request), "a late response has no waiter");
}

#[cfg(unix)]
mod daemon {
    use super::*;
    use crate::computer_capability::app_use::{ConfigFiles, LiveAppUse};
    use cerebellum_core::config::AppUse;
    use cortexkit_test_support::ScratchDir;
    use std::{
        fs,
        path::{Path, PathBuf},
        time::Duration,
    };
    use subc_control::ClientControlRequest;
    use subc_daemon::router::{FrameSink, OutboundFrame};
    use subc_daemon::{
        ConnectionId, ControlHandler, ForwardingTable, Registry, RouteCtx, SupervisorHandle,
    };
    use subc_protocol::manifest::{
        Concurrency, ExecutionMode, IdentityScope, ModuleManifest, ProviderRole, Tool,
    };
    use subc_protocol::session::{ModuleControlRequest, ModuleControlResponse};
    use subc_protocol::{
        BindIdentity, ModuleHelloAckBody, ModuleHelloBody, RouteTarget, PROTOCOL_VERSION,
    };
    use tokio::time::timeout;

    const TEST_NAME: &str =
        "computer_capability::operator_confirm::tests::daemon::operator_confirm_daemon_scenarios";

    fn frame(kind: FrameType, corr: u64, body: serde_json::Value) -> Frame {
        Frame::build(
            kind,
            crate::control_flags(),
            0,
            0,
            corr,
            serde_json::to_vec(&body).unwrap(),
        )
        .unwrap()
    }

    fn ctx(id: u64) -> (RouteCtx, mpsc::Receiver<OutboundFrame>) {
        let (tx, rx) = mpsc::channel(16);
        (
            RouteCtx {
                connection_id: ConnectionId::new(id),
                egress: FrameSink::new(tx),
            },
            rx,
        )
    }

    async fn receive(rx: &mut mpsc::Receiver<OutboundFrame>) -> Frame {
        timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("daemon reply deadline")
            .expect("daemon egress open")
            .frame
    }

    fn script_executable(path: &Path) -> bool {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("ckdev-"))
    }

    #[test]
    fn script_guard_rejects_an_executable_that_would_use_the_os_provider() {
        assert!(!script_executable(Path::new("cerebellum-tests")));
        assert!(script_executable(Path::new("ckdev-cerebellum-tests")));
    }

    struct Files;
    impl ConfigFiles for Files {
        fn modified(&self, path: &Path) -> std::io::Result<std::time::SystemTime> {
            fs::metadata(path)?.modified()
        }
        fn read_to_string(&self, path: &Path) -> std::io::Result<String> {
            fs::read_to_string(path)
        }
    }

    struct Fixture {
        root: ScratchDir,
        call: Call,
        pumps: Vec<tokio::task::JoinHandle<()>>,
        _client_rx: mpsc::Receiver<OutboundFrame>,
        handler: Arc<ControlHandler>,
        client: RouteCtx,
        client_route: (u16, u32),
        config: PathBuf,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            for task in &self.pumps {
                task.abort();
            }
        }
    }

    impl Fixture {
        async fn start(script: &str) -> Self {
            // The daemon otherwise silently retains its OS provider. Assert its
            // exact selection condition before configuring any test prompt.
            assert!(
                script_executable(&std::env::current_exe().unwrap()),
                "operator tests must run a ckdev- copy; refusing to reach the OS provider"
            );
            let root = ScratchDir::new("cerebellum-operator-confirm");
            let script_path = root.join("operator.script");
            let events = root.join("operator.events");
            fs::write(
                &script_path,
                script.replace("$RELEASE", root.join("release").to_str().unwrap()),
            )
            .unwrap();
            assert!(script_path.is_file());
            let forwarding = Arc::new(ForwardingTable::default());
            forwarding.configure_operator_script(&script_path, Some(&events), None);
            let supervisor = SupervisorHandle::new();
            supervisor.set_spawn_nonce("cerebellum", "fixture-nonce".into());
            let handler = Arc::new(
                ControlHandler::with_forwarding(Arc::new(Registry::default()), forwarding.clone())
                    .with_supervisor(supervisor),
            );
            let (module, mut module_rx) = ctx(1);
            let manifest = ModuleManifest::builder("cerebellum", "0.1.0")
                .protocol_ver(PROTOCOL_VERSION)
                .provides(vec![ProviderRole::ToolProvider {
                    tools: vec![Tool {
                        name: "computer.wait".into(),
                        description: None,
                        execution_mode: ExecutionMode::Pure,
                        schema: json!({}),
                    }],
                    identity_scope: vec![IdentityScope::Project, IdentityScope::Session],
                    concurrency: Concurrency::ModuleManaged,
                    emits_push: true,
                    sub_supervises: false,
                }])
                .build();
            let hello = ModuleHelloBody {
                manifest,
                protocol_ver: PROTOCOL_VERSION,
                control_ops: None,
                launch_nonce: Some("fixture-nonce".into()),
            };
            assert!(handler
                .handle_control_frame(
                    &module,
                    frame(FrameType::Hello, 1, serde_json::to_value(hello).unwrap())
                )
                .await
                .unwrap()
                .is_empty());
            let ack: ModuleHelloAckBody =
                serde_json::from_slice(&receive(&mut module_rx).await.body).unwrap();
            assert!(ack.subc_ops.contains(&"operator.confirm".into()));
            let (client, mut client_rx) = ctx(2);
            let open = ClientControlRequest::RouteOpen {
                target: RouteTarget::ToolProvider {
                    module_id: "cerebellum".into(),
                },
                identity: BindIdentity::new(root.path().to_path_buf(), "unit", "operator-test"),
                consumer_identity: None,
                consumer_capabilities: None,
                role_versions: None,
                admission_facts: None,
                scope: None,
            };
            let open_task = {
                let handler = handler.clone();
                let client = client.clone();
                tokio::spawn(async move {
                    handler
                        .handle_control_frame(
                            &client,
                            frame(FrameType::Request, 2, serde_json::to_value(open).unwrap()),
                        )
                        .await
                        .unwrap()
                })
            };
            let bind = receive(&mut module_rx).await;
            let route = match serde_json::from_slice::<ModuleControlRequest>(&bind.body).unwrap() {
                ModuleControlRequest::RouteBind {
                    route_channel,
                    epoch,
                    ..
                } => (route_channel, epoch),
                other => panic!("expected route.bind, got {other:?}"),
            };
            handler
                .handle_control_frame(
                    &module,
                    frame(
                        FrameType::Response,
                        bind.header.corr,
                        serde_json::to_value(ModuleControlResponse::RouteBindAck {}).unwrap(),
                    ),
                )
                .await
                .unwrap();
            let immediate = open_task.await.unwrap();
            let opened = if immediate.is_empty() {
                receive(&mut client_rx).await
            } else {
                immediate.into_iter().next().unwrap()
            };
            let opened: serde_json::Value = serde_json::from_slice(&opened.body).unwrap();
            let client_route = (
                opened["route_channel"].as_u64().unwrap() as u16,
                opened["route_epoch"].as_u64().unwrap() as u32,
            );
            let wire = Arc::new(Wire::default());
            let (writer, mut outgoing) = mpsc::channel(16);
            let request_pump = {
                let handler = handler.clone();
                let module = module.clone();
                let wire = wire.clone();
                tokio::spawn(async move {
                    while let Some(request) = outgoing.recv().await {
                        for response in handler
                            .handle_control_frame(&module, request)
                            .await
                            .unwrap()
                        {
                            wire.deliver(&response);
                        }
                    }
                })
            };
            let response_pump = {
                let wire = wire.clone();
                tokio::spawn(async move {
                    while let Some(response) = module_rx.recv().await {
                        wire.deliver(&response.frame);
                    }
                })
            };
            let config = std::env::var_os("CEREBELLUM_OPERATOR_CONFIG")
                .map(PathBuf::from)
                .unwrap_or_else(|| root.join("cerebellum.jsonc"));
            if !config.exists() {
                fs::write(&config, r#"{"computer_use":{"app_use":"foreground"}}"#).unwrap();
            }
            Self {
                root,
                call: Call {
                    wire,
                    writer,
                    route,
                },
                pumps: vec![request_pump, response_pump],
                _client_rx: client_rx,
                handler,
                client,
                client_route,
                config,
            }
        }

        fn live(&self) -> LiveAppUse {
            LiveAppUse::new(Some(self.config.clone()), Arc::new(Files))
        }

        async fn mode(
            &self,
            live: &LiveAppUse,
            cancel: &crate::CancelHandle,
        ) -> (AppUse, Option<String>) {
            crate::tool_result::APP_USE_NOTE
                .scope(
                    std::cell::RefCell::new(None),
                    CALL.scope(self.call.clone(), async {
                        let mode = live.current().unwrap();
                        let mode = live.approved_mode(mode, cancel).await;
                        (
                            mode,
                            crate::tool_result::APP_USE_NOTE.with(|note| note.borrow().clone()),
                        )
                    }),
                )
                .await
        }

        fn events(&self) -> Vec<serde_json::Value> {
            fs::read_to_string(self.root.join("operator.events"))
                .unwrap_or_default()
                // The provider writes concurrently; a trailing fragment is not
                // an event until its newline has been written.
                .split_inclusive('\n')
                .filter(|line| line.ends_with('\n'))
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        }
        fn prompts(&self) -> usize {
            self.events()
                .iter()
                .filter(|event| event["event"] == "prompt_shown")
                .count()
        }
        async fn event(&self, name: &str) {
            timeout(Duration::from_secs(5), async {
                while !self.events().iter().any(|event| event["event"] == name) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("script provider event deadline");
        }
    }

    async fn approvals_and_changes() {
        let f = Fixture::start("approve\napprove\napprove\n").await;
        let live = f.live();
        let cancel = crate::CancelHandle::pending();
        assert_eq!(f.mode(&live, &cancel).await, (AppUse::Foreground, None));
        assert_eq!(f.mode(&live, &cancel).await, (AppUse::Foreground, None));
        assert_eq!(f.prompts(), 1, "approval is reused by the second call");
        let set = |mode: &str, tick| {
            fs::write(
                &f.config,
                format!(r#"{{"computer_use":{{"app_use":"{mode}"}}}}"#),
            )
            .unwrap();
            fs::File::open(&f.config)
                .unwrap()
                .set_times(
                    std::fs::FileTimes::new()
                        .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(tick)),
                )
                .unwrap();
        };
        set("foreground", 1);
        assert_eq!(f.mode(&live, &cancel).await.0, AppUse::Foreground);
        assert_eq!(
            f.prompts(),
            1,
            "approval keys the parsed value, not the file's bytes or timestamp"
        );
        set("background", 2);
        assert_eq!(f.mode(&live, &cancel).await, (AppUse::Background, None));
        assert_eq!(f.prompts(), 1, "narrowing never asks");
        set("foreground", 3);
        assert_eq!(f.mode(&live, &cancel).await.0, AppUse::Foreground);
        assert_eq!(f.prompts(), 2, "switching back needs fresh approval");
        fs::write(&f.config, "not JSON").unwrap();
        assert!(live.current().is_err());
        set("foreground", 4);
        assert_eq!(f.mode(&live, &cancel).await.0, AppUse::Foreground);
        assert_eq!(f.prompts(), 3, "an unknown setting also ends approval");
    }

    async fn failures_and_deadlines() {
        let cancel = crate::CancelHandle::pending();
        let f = Fixture::start("decline\napprove\n").await;
        let live = f.live();
        let (mode, note) = f.mode(&live, &cancel).await;
        assert_eq!(mode, AppUse::Background);
        assert!(note.unwrap().contains("declined"));
        let (mode, note) = f.mode(&live, &cancel).await;
        assert_eq!(mode, AppUse::Background);
        let note = note.unwrap();
        assert!(
            note.contains("retry after") && note.contains("ms"),
            "{note}"
        );
        assert_eq!(f.prompts(), 1, "the decline hold does not re-prompt");

        let f = Fixture::start("unavailable\n").await;
        let (mode, note) = f.mode(&f.live(), &cancel).await;
        assert_eq!(mode, AppUse::Background);
        assert!(note.unwrap().contains("presence is unavailable"));
        assert_eq!(f.prompts(), 1);

        let f = Fixture::start("approve\n").await;
        let live = f.live();
        let (mode, note) = crate::call_context::CALL_DEADLINE
            .scope(
                tokio::time::Instant::now() + Duration::from_secs(20),
                f.mode(&live, &cancel),
            )
            .await;
        assert_eq!(mode, AppUse::Background);
        assert!(note.unwrap().contains("call's time limit"));
        assert_eq!(f.prompts(), 0, "a too-short call never starts a prompt");
        let mut wrong_route = f.call.clone();
        wrong_route.route.1 += 1;
        assert_eq!(
            CALL.scope(wrong_route, confirm()).await,
            Err(Failure::NotPermitted)
        );
        assert_eq!(f.prompts(), 0, "a different epoch cannot lend authority");
    }

    async fn concurrent_calls_share_one_prompt() {
        let f = Fixture::start("approve when $RELEASE\n").await;
        let live = f.live();
        let first = crate::CancelHandle::pending();
        let second = crate::CancelHandle::pending();
        let calls = async { tokio::join!(f.mode(&live, &first), f.mode(&live, &second)) };
        let release = async {
            f.event("prompt_shown").await;
            tokio::task::yield_now().await;
            assert_eq!(f.prompts(), 1);
            fs::write(f.root.join("release"), "go").unwrap();
        };
        let ((first, second), ()) = tokio::join!(calls, release);
        assert_eq!(first, (AppUse::Foreground, None));
        assert_eq!(second, (AppUse::Foreground, None));
        assert_eq!(f.prompts(), 1);
    }

    async fn cancel_and_goodbye_withdraw() {
        let f = Fixture::start("hang\napprove\n").await;
        let live = f.live();
        let cancel = crate::CancelHandle::pending();
        let waiting = f.mode(&live, &cancel);
        tokio::pin!(waiting);
        tokio::select! {
            _ = &mut waiting => panic!("hang must await cancellation"),
            _ = f.event("prompt_shown") => {},
        }
        cancel.cancel();
        assert_eq!(waiting.await.0, AppUse::Background);
        f.event("withdraw").await;
        f.event("provider_returned").await;
        assert_eq!(f.prompts(), 1);
        assert_eq!(
            f.mode(&live, &crate::CancelHandle::pending()).await.0,
            AppUse::Foreground,
            "a cancelled prompt never seeds approval"
        );
        assert_eq!(f.prompts(), 2);

        let f = Fixture::start("hang\n").await;
        let live = f.live();
        let cancel = crate::CancelHandle::pending();
        let waiting = f.mode(&live, &cancel);
        tokio::pin!(waiting);
        tokio::select! {
            _ = &mut waiting => panic!("hang must await route closure"),
            _ = f.event("prompt_shown") => {},
        }
        let goodbye = Frame::build(
            FrameType::Goodbye,
            crate::control_flags(),
            f.client_route.0,
            f.client_route.1,
            0,
            Vec::new(),
        )
        .unwrap();
        subc_daemon::Router::with_control_handler(f.handler.clone())
            .route_for_connection(&f.client, goodbye)
            .await
            .unwrap();
        assert_eq!(
            timeout(Duration::from_secs(5), waiting).await.unwrap().0,
            AppUse::Background
        );
        f.event("withdraw").await;
    }

    #[test]
    fn operator_confirm_daemon_scenarios() {
        if std::env::var_os("CEREBELLUM_OPERATOR_CHILD").is_none() {
            let binary = cortexkit_test_support::ckdev_binary(std::env::current_exe().unwrap());
            let restart = ScratchDir::new("cerebellum-operator-restart");
            let config = restart.join("cerebellum.jsonc");
            fs::write(&config, r#"{"computer_use":{"app_use":"foreground"}}"#).unwrap();
            for scenario in ["all", "restart", "restart"] {
                let mut command = std::process::Command::new(&binary);
                command
                    .args(["--exact", TEST_NAME, "--nocapture"])
                    .env("CEREBELLUM_OPERATOR_CHILD", scenario);
                if scenario == "restart" {
                    command.env("CEREBELLUM_OPERATOR_CONFIG", &config);
                }
                let status = command.status().unwrap();
                assert!(status.success(), "operator scenario {scenario} failed");
            }
            return;
        }
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                if std::env::var("CEREBELLUM_OPERATOR_CHILD").unwrap() == "restart" {
                    let f = Fixture::start("approve\n").await;
                    assert_eq!(
                        f.mode(&f.live(), &crate::CancelHandle::pending()).await.0,
                        AppUse::Foreground
                    );
                    assert_eq!(
                        f.prompts(),
                        1,
                        "each new process must ask, not trust a stored marker"
                    );
                    return;
                }
                approvals_and_changes().await;
                failures_and_deadlines().await;
                concurrent_calls_share_one_prompt().await;
                cancel_and_goodbye_withdraw().await;
            });
    }
}
