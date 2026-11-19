use super::*;
use subc_protocol::config::{ConfigGetReply, ConfigStatus, ConfigView};
use subc_transport::frame_io::write_frame;

fn frame(ty: FrameType, channel: u16, epoch: u32, corr: u64, value: Value) -> Frame {
    Frame::build(
        ty,
        control_flags(),
        channel,
        epoch,
        corr,
        serde_json::to_vec(&value).unwrap(),
    )
    .unwrap()
}

fn body(frame: &Frame) -> Value {
    serde_json::from_slice(&frame.body).unwrap()
}

fn declaration() -> subc_protocol::config::ConfigDeclareRequest {
    settings::config_declaration(std::path::Path::new("/fixture/cerebellum.jsonc")).unwrap()
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn browser_controls_check_the_executable_only_for_own_launch() {
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        None,
        JournalPersistence::Isolated,
    );
    planes.runtime_browser = Some(BrowserSurface::NotConfigured);
    let (writer, mut replies) = mpsc::channel(8);
    for (corr, args, expected) in [
        (1, json!({"action":"status"}), "no_session"),
        (2, json!({"action":"status","browser":"user"}), "ok"),
        (
            3,
            json!({"action":"close","browser_session_id":"absent"}),
            "browser_session_not_found",
        ),
        (4, json!({"action":"launch"}), "executable_missing"),
    ] {
        let request = frame(
            FrameType::Request,
            4,
            1,
            corr,
            json!({"name":"browser_use","arguments":args}),
        );
        handle_tool_request_for_test_with_planes(request, &writer, &planes)
            .await
            .unwrap();
        let reply = replies.try_recv().unwrap();
        let value = body(&reply);
        assert_eq!(reply.header.ty, FrameType::Response, "{value}");
        assert_eq!(value["outcome"], expected, "{value}");
        if corr == 2 {
            assert_eq!(value["browser"], "user");
            assert_eq!(value["connected"], false);
            assert_eq!(value["tabs"], json!([]));
        }
        if corr == 4 {
            assert!(
                value["reason"]
                    .as_str()
                    .unwrap()
                    .contains("browser.executable_path"),
                "{value}"
            );
        }
    }
}

#[tokio::test]
async fn settings_startup_serves_review_and_waits_for_the_effective_view() {
    let (mut reader, mut daemon) = tokio::io::duplex(4096);
    let mut incoming = Incoming::new(&mut reader, read_one);
    let (writer, mut sent) = mpsc::channel(8);
    let session = Session::new(PROTOCOL_VERSION);
    let mut waiting = VecDeque::new();
    let work = async { Ok(session.initial(&writer, declaration()).await) };
    let server = wait_for_startup(
        &mut incoming,
        &writer,
        Some(&session),
        "cerebellum",
        &mut waiting,
        work,
    );
    let daemon = async {
        let declare = sent.recv().await.unwrap();
        assert_eq!(declare.header.channel, 0);
        assert_eq!(body(&declare)["op"], "config.declare");
        assert_eq!(body(&declare)["user_file"], "/fixture/cerebellum.jsonc");
        write_frame(
            &mut daemon,
            &frame(
                FrameType::Response,
                0,
                0,
                declare.header.corr,
                json!({"op":"config.declare"}),
            ),
        )
        .await
        .unwrap();
        let get = sent.recv().await.unwrap();
        assert_eq!(body(&get)["op"], "config.get");
        let early_call = frame(FrameType::Request, 4, 1, 21, json!({}));
        write_frame(&mut daemon, &early_call).await.unwrap();
        let review = frame(
            FrameType::Request,
            0,
            0,
            22,
            json!({"op":"config.review","layers":[],"base_generation":0,"base":null}),
        );
        write_frame(&mut daemon, &review).await.unwrap();
        let reply = sent.recv().await.unwrap();
        assert_eq!(reply.header.corr, review.header.corr);
        assert_eq!(reply.header.ty, FrameType::Response);
        assert_eq!(body(&reply)["fields"].as_array().unwrap().len(), 11);
        let mut view = ConfigView::new(
            12,
            json!({"health":{"queue_age_stale_ms":1234},"computer_use":{"agent_cursor":false,"app_use":"foreground"}}),
            Default::default(),
            vec![],
            ConfigStatus::Pending,
        );
        view.attempt = Some(34);
        let reply = serde_json::to_value(ConfigGetReply::new(None, Some(view))).unwrap();
        write_frame(
            &mut daemon,
            &frame(FrameType::Response, 0, 0, get.header.corr, reply),
        )
        .await
        .unwrap();
        // Keep the transport open until startup processing observes the view.
        daemon
    };
    let (result, _daemon) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(server, daemon)
    })
    .await
    .unwrap();
    let (startup, report) = result.unwrap().unwrap().unwrap();
    assert_eq!(waiting.pop_front().unwrap().header.corr, 21);
    assert_eq!(startup.health.queue_age_stale_ms, 1234);
    assert!(!startup.agent_cursor);
    assert!(startup.live.approved);
    let report = report.unwrap();
    assert_eq!(report.generation, 12);
    assert_eq!(report.attempt, 34);
    assert!(report.result.is_ack());
}

#[tokio::test(start_paused = true)]
async fn settings_startup_times_out_early_calls_without_falling_back() {
    let (mut reader, mut daemon) = tokio::io::duplex(4096);
    let mut incoming = Incoming::new(&mut reader, read_one);
    let (writer, mut sent) = mpsc::channel(8);
    let session = Session::new(PROTOCOL_VERSION);
    let mut waiting = VecDeque::new();
    let work = async { Ok(session.initial(&writer, declaration()).await) };
    let server = wait_for_startup(
        &mut incoming,
        &writer,
        Some(&session),
        "cerebellum",
        &mut waiting,
        work,
    );
    let daemon = async {
        let declare = sent.recv().await.unwrap();
        assert_eq!(body(&declare)["op"], "config.declare");
        write_frame(
            &mut daemon,
            &frame(
                FrameType::Response,
                0,
                0,
                declare.header.corr,
                json!({"op":"config.declare"}),
            ),
        )
        .await
        .unwrap();
        let get = sent.recv().await.unwrap();
        assert_eq!(body(&get)["op"], "config.get");
        write_frame(
            &mut daemon,
            &frame(
                FrameType::Error,
                0,
                0,
                get.header.corr,
                json!({"code":"config_gated","message":"no approved view"}),
            ),
        )
        .await
        .unwrap();
        write_frame(
            &mut daemon,
            &frame(FrameType::Request, 0, 0, 21, json!({"op":"health.check"})),
        )
        .await
        .unwrap();
        let health = sent.recv().await.unwrap();
        assert_eq!(health.header.corr, 21);
        assert_eq!(health.header.ty, FrameType::Response);
        assert_eq!(body(&health)["status"], "degraded");
        assert_eq!(
            body(&health)["detail"],
            "settings_view_missing: config_gated"
        );

        write_frame(
            &mut daemon,
            &frame(
                FrameType::Push,
                0,
                0,
                0,
                json!({"op":"config.changed","generation":0,"fields":[]}),
            ),
        )
        .await
        .unwrap();
        let get = sent.recv().await.unwrap();
        assert_eq!(body(&get)["op"], "config.get");
        // Keep the original correlation even after queued calls time out and
        // the module has waited a full minute without a view.
        tokio::time::advance(Duration::from_secs(61)).await;
        write_frame(&mut daemon, &frame(FrameType::Request, 4, 1, 22, json!({})))
            .await
            .unwrap();
        let response = sent.recv().await.unwrap();
        assert_eq!(response.header.corr, 22);
        assert_eq!(response.header.ty, FrameType::Error);
        assert_eq!(body(&response)["code"], "not_ready");
        write_frame(
            &mut daemon,
            &frame(FrameType::Request, 0, 0, 23, json!({"op":"health.check"})),
        )
        .await
        .unwrap();
        let health = sent.recv().await.unwrap();
        assert_eq!(health.header.corr, 23);
        assert_eq!(health.header.ty, FrameType::Response);
        assert_eq!(body(&health)["status"], "degraded");

        let view = ConfigView::new(
            0,
            json!({"health":{"queue_age_stale_ms":4321}}),
            Default::default(),
            vec![],
            ConfigStatus::Unstamped,
        );
        let reply = serde_json::to_value(ConfigGetReply::new(Some(view), None)).unwrap();
        write_frame(
            &mut daemon,
            &frame(FrameType::Response, 0, 0, get.header.corr, reply),
        )
        .await
        .unwrap();
        daemon
    };
    let (result, _daemon) = tokio::time::timeout(Duration::from_secs(90), async {
        tokio::join!(server, daemon)
    })
    .await
    .unwrap();
    let (startup, _) = result
        .unwrap()
        .unwrap()
        .expect("wait for the managed view, not the legacy file");
    assert_eq!(startup.health.queue_age_stale_ms, 4321);
    assert!(startup.legacy_file.is_none());
    assert!(waiting.is_empty());
}

#[tokio::test]
async fn settings_declare_refusal_selects_fallback_and_a_later_view_clears_degradation() {
    let (writer, mut sent) = mpsc::channel(8);
    let session = Session::new(PROTOCOL_VERSION);
    let (applied, mut live) = tokio::sync::watch::channel(LiveSettings::default());
    let (refused, ready) = tokio::sync::oneshot::channel();
    let driver = async {
        assert!(session.initial(&writer, declaration()).await.is_err());
        refused.send(()).unwrap();
        session
            .live(&writer, None, move |settings| {
                applied.send_replace(settings);
            })
            .await;
    };
    let daemon = async {
        let declare = sent.recv().await.unwrap();
        assert_eq!(body(&declare)["op"], "config.declare");
        assert!(session.take(&frame(
            FrameType::Error,
            0,
            0,
            declare.header.corr,
            json!({"code":"schema_invalid","message":"invalid schema"})
        )));
        ready.await.unwrap();
        let mut health = HealthState::new().report();
        session.annotate_health(&mut health);
        assert_eq!(
            serde_json::to_value(health).unwrap()["detail"],
            "settings_declaration_refused: schema_invalid"
        );
        assert!(session.take(&frame(
            FrameType::Push,
            0,
            0,
            0,
            json!({"op":"config.changed","generation":1,"fields":["/computer_use/app_use"]})
        )));
        let get = sent.recv().await.unwrap();
        assert_eq!(body(&get)["op"], "config.get");
        let mut view = ConfigView::new(
            1,
            json!({"computer_use":{"app_use":"foreground"}}),
            Default::default(),
            vec![],
            ConfigStatus::Pending,
        );
        view.attempt = Some(2);
        let reply = serde_json::to_value(ConfigGetReply::new(None, Some(view))).unwrap();
        assert!(session.take(&frame(FrameType::Response, 0, 0, get.header.corr, reply)));
        live.changed().await.unwrap();
        assert_eq!(
            *live.borrow(),
            LiveSettings {
                app_use: cerebellum_core::config::AppUse::Foreground,
                approved: true
            }
        );
        let report = sent.recv().await.unwrap();
        let applied: ConfigAppliedRequest = serde_json::from_slice(&report.body).unwrap();
        assert!(applied.result.is_ack());
        let mut health = HealthState::new().report();
        session.annotate_health(&mut health);
        assert_eq!(serde_json::to_value(health).unwrap()["status"], "ok");
    };
    tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! { () = daemon => {}, () = driver => panic!("live watcher exited") }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn settings_live_hint_fetches_and_applies_a_new_view_without_restart() {
    let (writer, mut sent) = mpsc::channel(8);
    let session = Session::new(PROTOCOL_VERSION);
    let (installed, mut updates) = tokio::sync::watch::channel(LiveSettings::default());
    let driver = session.live(&writer, None, move |settings| {
        installed.send_replace(settings);
    });
    let daemon = async {
        assert!(session.take(&frame(
            FrameType::Push,
            0,
            0,
            0,
            json!({"op":"config.changed","generation":0,"fields":["/computer_use/app_use"]})
        )));
        let get = sent.recv().await.unwrap();
        assert_eq!(body(&get)["op"], "config.get");
        let view = ConfigView::new(
            0,
            json!({"computer_use":{"app_use":"foreground"},"health":{"queue_age_stale_ms":4242}}),
            Default::default(),
            vec![],
            ConfigStatus::Unstamped,
        );
        let reply = serde_json::to_value(ConfigGetReply::new(Some(view), None)).unwrap();
        assert!(session.take(&frame(FrameType::Response, 0, 0, get.header.corr, reply)));
        updates.changed().await.unwrap();
        assert_eq!(
            *updates.borrow(),
            LiveSettings {
                app_use: cerebellum_core::config::AppUse::Foreground,
                approved: false
            }
        );
    };
    tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! { () = daemon => {}, () = driver => panic!("live watcher exited") }
    })
    .await
    .unwrap();
}

#[tokio::test]
#[cfg(unix)]
async fn settings_hello_manifest_matches_old_configured_hello_except_for_review_opt_in() {
    let contents = include_str!("../tests/fixtures/legacy-macos-settings.jsonc");
    let mut config = ModuleConfig {
        connection_file_path: PathBuf::from("fixture"),
        module_id: "cerebellum".into(),
        health: parse_config(contents).unwrap().health,
        agent_cursor: true,
        browser: BrowserSurface::Available(
            browser_config::parse_browser_config(contents)
                .unwrap()
                .unwrap(),
        ),
    };
    let (writer, mut sent) = mpsc::channel(2);
    send_hello(&writer, &config, false, false).await.unwrap();
    let previous = sent.recv().await.unwrap();
    for surface in [config.browser.clone(), BrowserSurface::NotConfigured] {
        config.browser = surface;
        send_hello(&writer, &config, true, true).await.unwrap();
        let new = sent.recv().await.unwrap();
        let mut new = body(&new);
        assert_eq!(
            new["control_ops"].as_array_mut().unwrap().pop(),
            Some(json!("config.review"))
        );
        assert_eq!(
            serde_json::to_vec(&new).unwrap(),
            previous.body,
            "HELLO (including flat tool definitions) changed apart from config.review"
        );
    }
}
