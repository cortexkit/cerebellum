use super::*;
use crate::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::{mpsc, Notify};

#[allow(dead_code)]
mod computer_support {
    use crate as cerebellum;
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/it/support/computer.rs"
    ));
}

struct DisplayDouble {
    modules: Vec<String>,
    writes: Mutex<Vec<DisplayWrite>>,
    wrote: Notify,
    stall: bool,
    fail: bool,
}

impl DisplayDouble {
    fn new(modules: &[&str]) -> Arc<Self> {
        Arc::new(Self {
            modules: modules.iter().map(|s| (*s).into()).collect(),
            writes: Mutex::new(vec![]),
            wrote: Notify::new(),
            stall: false,
            fail: false,
        })
    }
    async fn count(&self, expected: usize) {
        tokio::time::timeout(crate::test_support::HANG_GUARD, async {
            loop {
                let notified = self.wrote.notified();
                if self.writes.lock().unwrap().len() >= expected {
                    break;
                }
                notified.await;
            }
        })
        .await
        .expect("display received writes");
    }
}
impl Backend for DisplayDouble {
    fn declarers(&self) -> Future<'_, Option<Vec<String>>> {
        Box::pin(async { Some(self.modules.clone()) })
    }
    fn write<'a>(&'a self, _module: &'a str, write: DisplayWrite) -> Future<'a, bool> {
        Box::pin(async move {
            self.writes.lock().unwrap().push(write);
            self.wrote.notify_one();
            if self.stall {
                std::future::pending::<()>().await;
            }
            !self.fail
        })
    }
}

struct CatalogDouble {
    answer: Mutex<Option<Vec<String>>>,
    reads: AtomicUsize,
    blocked: AtomicBool,
    release: tokio::sync::Semaphore,
}

impl CatalogDouble {
    fn new(modules: &[&str]) -> Arc<Self> {
        Arc::new(Self {
            answer: Mutex::new(Some(
                modules.iter().map(|module| (*module).into()).collect(),
            )),
            reads: AtomicUsize::new(0),
            blocked: AtomicBool::new(false),
            release: tokio::sync::Semaphore::new(0),
        })
    }
}

impl Backend for CatalogDouble {
    fn declarers(&self) -> Future<'_, Option<Vec<String>>> {
        Box::pin(async {
            self.reads.fetch_add(1, Ordering::SeqCst);
            if self.blocked.load(Ordering::SeqCst) {
                self.release.acquire().await.unwrap().forget();
            }
            self.answer.lock().unwrap().clone()
        })
    }

    fn write<'a>(&'a self, _module: &'a str, _write: DisplayWrite) -> Future<'a, bool> {
        Box::pin(async { false })
    }
}

fn planes() -> Planes {
    Planes::with_browser_config_journaling(
        Arc::new(cerebellum_core::health::HealthState::new()),
        Some(Planes::short_test_browser_config()),
        JournalPersistence::Isolated,
    )
}

fn frame(body: Value) -> Frame {
    Frame::build(
        FrameType::Request,
        control_flags(),
        7,
        1,
        10,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap()
}

fn browser_pin() -> String {
    let names = tool_provider::browser_tools()
        .into_iter()
        .map(|tool| tool.name)
        .collect::<Vec<_>>();
    let tool = flat_tools::browser_tool(&names).unwrap();
    let digest = cortexkit_role_tool_provider::catalog::schema_digest(&tool.schema).unwrap();
    cortexkit_role_tool_provider::call::SchemaPin::new(tool.name, digest, 1)
        .encode()
        .unwrap()
}

fn request() -> Value {
    json!({"name":"browser_use","call_key":"pf:local","schema_pin":browser_pin(),
        "origin":{"carrier":{"kind":"reserved","module_id":"runner"},"call_key":"runner:call","schema_pin":"runner-served-pin"},
        "arguments":{"action":"status"}})
}

fn install(planes: &Planes) -> crate::AcceptedBindFacts {
    install_browser_test_bind(&planes.routes, 7, 1, &["browser.status"]);
    planes.routes.get(7, 1).unwrap()
}

async fn arm_health_metrics(planes: &Planes) -> Value {
    let mut request = frame(serde_json::to_value(ModuleControlRequest::HealthCheck {}).unwrap());
    request.header.channel = 0;
    let (writer, mut replies) = mpsc::channel(8);
    handle_control_request(request, &writer, &planes.health, &planes.routes, None, None)
        .await
        .unwrap();
    let reply = replies.recv().await.unwrap();
    let ModuleControlResponse::HealthCheck {
        metrics: Some(metrics),
        ..
    } = serde_json::from_slice(&reply.body).unwrap()
    else {
        panic!("health reply");
    };
    metrics["toolDisplay"].clone()
}

fn arm_counts(counter: &str) -> Value {
    let mut counts = json!({
        "armed":0,
        "noSchemaPin":0,
        "noCallKey":0,
        "invalidOrigin":0,
        "invalidKeyOrPin":0,
        "duplicate":0,
        "unparsed":0,
        "noPrincipal":0,
    });
    counts[counter] = json!(1);
    counts
}

#[tokio::test]
async fn arm_health_reports_armed_for_browser_and_computer_only() {
    for name in [flat_tools::BROWSER_USE, flat_tools::COMPUTER_USE] {
        let planes = planes();
        let facts = install(&planes);
        let mut call = request();
        call["name"] = json!(name);
        assert!(planes.routes.display.arm(&frame(call), &facts).is_some());
        let mut unrelated = request();
        unrelated["name"] = json!("tool.catalog");
        assert!(planes
            .routes
            .display
            .arm(&frame(unrelated), &facts)
            .is_none());
        assert_eq!(arm_health_metrics(&planes).await, arm_counts("armed"));
    }
}

#[tokio::test]
async fn arm_health_reports_missing_schema_pin_for_relayed_and_direct_calls() {
    for relayed in [true, false] {
        let planes = planes();
        let facts = install(&planes);
        let mut call = request();
        if relayed {
            call["origin"].as_object_mut().unwrap().remove("schema_pin");
        } else {
            call.as_object_mut().unwrap().remove("origin");
            call.as_object_mut().unwrap().remove("schema_pin");
        }
        assert!(planes.routes.display.arm(&frame(call), &facts).is_none());
        assert_eq!(arm_health_metrics(&planes).await, arm_counts("noSchemaPin"));
    }
}

#[tokio::test]
async fn arm_health_reports_missing_call_key() {
    let planes = planes();
    let facts = install(&planes);
    let mut call = request();
    call.as_object_mut().unwrap().remove("origin");
    call.as_object_mut().unwrap().remove("call_key");
    assert!(planes.routes.display.arm(&frame(call), &facts).is_none());
    assert_eq!(arm_health_metrics(&planes).await, arm_counts("noCallKey"));
}

#[tokio::test]
async fn arm_health_reports_invalid_origin() {
    let planes = planes();
    let facts = install(&planes);
    let mut call = request();
    call["origin"]["call_key"] = json!("");
    assert!(planes.routes.display.arm(&frame(call), &facts).is_none());
    assert_eq!(
        arm_health_metrics(&planes).await,
        arm_counts("invalidOrigin")
    );
}

#[tokio::test]
async fn arm_health_reports_invalid_key_or_pin() {
    for field in ["call_key", "schema_pin"] {
        let planes = planes();
        let facts = install(&planes);
        let mut call = request();
        call.as_object_mut().unwrap().remove("origin");
        call[field] = json!("");
        assert!(planes.routes.display.arm(&frame(call), &facts).is_none());
        assert_eq!(
            arm_health_metrics(&planes).await,
            arm_counts("invalidKeyOrPin")
        );
    }
}

#[tokio::test]
async fn arm_health_reports_duplicates_without_another_armed_count() {
    let planes = planes();
    let facts = install(&planes);
    let call = frame(request());
    assert!(planes.routes.display.arm(&call, &facts).is_some());
    assert!(planes.routes.display.arm(&call, &facts).is_none());
    let mut expected = arm_counts("armed");
    expected["duplicate"] = json!(1);
    assert_eq!(arm_health_metrics(&planes).await, expected);
}

async fn route_reply(planes: &Planes, call: Frame) -> Value {
    let (writer, mut replies) = mpsc::channel(32);
    handle_frame(call, &writer, planes).await.unwrap();
    let reply = tokio::time::timeout(crate::test_support::HANG_GUARD, replies.recv())
        .await
        .unwrap()
        .unwrap();
    serde_json::from_slice(&reply.body).unwrap()
}

#[tokio::test]
async fn relayed_prefrontal_status_sample_reports_no_schema_pin() {
    let planes = planes();
    let mut facts = install(&planes);
    facts.principal = Some(Principal::Reserved {
        module_id: "prefrontal-core".into(),
    });
    planes.routes.insert(7, 1, facts.clone());
    // Reconstructed relay body, including the original caller's slash-separated key.
    let body = br#"{"arguments":{"action":"status"},"call_key":"pf:39b7e70681f026216a4ca1efa6c4b6f9","name":"browser_use","origin":{"call_key":"msg_1e4085e85001iUy7R1Hq0nwm3A/toolu_01XiwEYbWXjj2i6uSjes7ViH","carrier":{"kind":"reserved","module_id":"thalamus-harness"}}}"#;
    let decoded: subc_protocol::tool_call::ToolCallRequest = serde_json::from_slice(body).unwrap();
    subc_protocol::tool_call::validate_call_key(decoded.call_key.as_ref().unwrap()).unwrap();
    subc_protocol::tool_call::validate_call_origin(decoded.origin.as_ref().unwrap()).unwrap();
    let mut call = frame(json!(null));
    call.body = body.to_vec();
    assert!(planes.routes.display.arm(&call, &facts).is_none());
    assert_eq!(planes.routes.display.metrics()["noSchemaPin"], 1);

    let planes = self::planes();
    planes.routes.insert(7, 1, facts);
    let reply = route_reply(&planes, call).await;
    assert_eq!(reply["outcome"], "no_session", "{reply}");
    assert_eq!(planes.routes.display.metrics()["noSchemaPin"], 1);
}

#[tokio::test]
async fn arm_health_reports_unparsed_json() {
    for (surface, body, unparsed) in [
        (RouteSurface::Tools, b"{".to_vec(), 1),
        (
            RouteSurface::Tools,
            serde_json::to_vec(&json!({"name":1,"arguments":{}})).unwrap(),
            1,
        ),
        (
            RouteSurface::Management,
            serde_json::to_vec(&json!({"method":"unknown","params":{}})).unwrap(),
            0,
        ),
    ] {
        let planes = planes();
        let mut facts = install(&planes);
        facts.surface = surface;
        planes.routes.insert(7, 1, facts);
        let mut call = frame(request());
        call.body = body;
        route_reply(&planes, call).await;
        let mut expected = arm_counts("unparsed");
        expected["unparsed"] = json!(unparsed);
        assert_eq!(arm_health_metrics(&planes).await, expected);
    }
}

#[tokio::test]
async fn arm_health_reports_no_principal_for_direct_call() {
    let planes = planes();
    let mut facts = install(&planes);
    facts.principal = None;
    planes.routes.insert(7, 1, facts);
    let mut call = request();
    call.as_object_mut().unwrap().remove("origin");
    route_reply(&planes, frame(call)).await;
    assert_eq!(arm_health_metrics(&planes).await, arm_counts("noPrincipal"));
}

async fn deliver(planes: &Planes, body: Value) {
    let mut reply = frame(body);
    reply.header.ty = FrameType::Response;
    let (tx, rx) = mpsc::channel(8);
    tx.send(reply).await.unwrap();
    drop(tx);
    crate::egress::drain_writer(tokio::io::sink(), rx, Arc::clone(&planes.egress_deadlines))
        .await
        .unwrap();
}

#[tokio::test]
async fn relayed_record_uses_origin_and_is_written_once_after_flush() {
    let planes = planes();
    let display = DisplayDouble::new(&["arbitrary-display-name"]);
    planes.routes.display.connect(display.clone());
    let facts = install(&planes);
    let mut call = request();
    call["schema_pin"] = json!("provider-local-pin");
    let req = frame(call);
    planes.routes.display.arm(&req, &facts).unwrap();
    assert!(display.writes.lock().unwrap().is_empty());
    deliver(&planes, json!({"outcome":"ok"})).await;
    display.count(1).await;
    assert!(planes.routes.display.arm(&req, &facts).is_none());
    deliver(&planes, json!({"outcome":"ok"})).await;
    let writes = display.writes.lock().unwrap();
    assert_eq!(writes.len(), 1);
    assert_eq!(
        writes[0].runner,
        Principal::Reserved {
            module_id: "runner".into()
        }
    );
    assert_eq!(writes[0].call_key, "runner:call");
    assert_eq!(writes[0].schema_pin, "runner-served-pin");
    assert_eq!(writes[0].kind, DisplayKind::Record);
    assert_eq!(writes[0].body["outcome"], "success");
    assert_eq!(writes[0].body["plane"], "browser");
    cortexkit_role_tool_display::schema::validate_record(&writes[0].body, &schema()).unwrap();
}

#[tokio::test(start_paused = true)]
async fn bus_notice_waits_for_flush_and_failure_leaves_reply_and_direct_display_untouched() {
    use std::{
        pin::Pin,
        sync::atomic::{AtomicBool, Ordering::Relaxed},
        task::{Context, Poll, Waker},
    };
    use tokio::io::AsyncWrite;

    #[derive(Default)]
    struct Gate {
        bytes: Mutex<Vec<u8>>,
        entered: AtomicBool,
        released: AtomicBool,
        waker: Mutex<Option<Waker>>,
    }
    struct Writer(Arc<Gate>);
    impl AsyncWrite for Writer {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.0.bytes.lock().unwrap().extend_from_slice(bytes);
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            self.0.entered.store(true, Relaxed);
            if self.0.released.load(Relaxed) {
                return Poll::Ready(Ok(()));
            }
            *self.0.waker.lock().unwrap() = Some(cx.waker().clone());
            Poll::Pending
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    for tool in ["browser_use", "computer_use"] {
        for stall in [false, true] {
            let planes = planes();
            let display = DisplayDouble::new(&["display"]);
            planes.routes.display.connect(display.clone());
            let fake = Arc::new(crate::event_publish::tests::Fake::default());
            fake.fail_publish.store(true, Relaxed);
            fake.hang_publish.store(stall, Relaxed);
            planes.routes.display.events.connect(Arc::new(fake.clone()));
            let facts = install(&planes);
            let mut request = request();
            request["name"] = json!(tool);
            if tool == "computer_use" {
                request["arguments"] = json!({"action":"read_state", "target":"com.example.app"});
            }
            planes.routes.display.arm(&frame(request), &facts).unwrap();
            let body = json!({"outcome":"ok", "screen_text":"planted-screen-text"});
            let mut reply = frame(body.clone());
            reply.header.ty = FrameType::Response;
            let (tx, rx) = mpsc::channel(8);
            tx.send(reply).await.unwrap();
            drop(tx);
            let gate = Arc::new(Gate::default());
            let writer = tokio::spawn(crate::egress::drain_writer(
                Writer(gate.clone()),
                rx,
                planes.egress_deadlines.clone(),
            ));
            crate::event_publish::tests::settle().await;
            assert!(gate.entered.load(Relaxed));
            assert!(
                fake.writes.lock().unwrap().is_empty(),
                "bus publish before reply flush"
            );
            assert!(display.writes.lock().unwrap().is_empty());
            gate.released.store(true, Relaxed);
            gate.waker.lock().unwrap().take().unwrap().wake();
            let at_flush = tokio::time::Instant::now();
            writer.await.unwrap().unwrap();
            assert_eq!(
                at_flush.elapsed(),
                Duration::ZERO,
                "bus must not hold egress"
            );
            display.count(1).await;
            crate::event_publish::tests::settle().await;
            let bytes = gate.bytes.lock().unwrap().clone();
            let emitted = subc_transport::read_frame(&mut bytes.as_slice())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&emitted.body).unwrap(),
                body
            );
            {
                let direct = display.writes.lock().unwrap().clone();
                let bus = fake.writes.lock().unwrap().clone();
                assert_eq!(direct.len(), 1);
                assert_eq!(bus.len(), 1);
                assert_eq!(
                    serde_json::from_slice::<Value>(&bus[0].bytes).unwrap(),
                    json!({"record_id":bus[0].id})
                );
                let retained = planes
                    .routes
                    .display
                    .events
                    .display_read(&bus[0].id)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(retained, serde_json::to_vec(&direct[0]).unwrap());
                assert!(!String::from_utf8_lossy(&retained).contains("planted-screen-text"));
                assert!(!String::from_utf8_lossy(&bus[0].bytes).contains("planted-screen-text"));
            }
            tokio::time::advance(Duration::from_secs(4)).await;
            crate::event_publish::tests::settle().await;
            assert_eq!(display.writes.lock().unwrap().len(), 1);
        }
    }
}

#[tokio::test]
async fn display_disk_write_failure_drops_wake_but_preserves_reply_and_direct_write() {
    let scratch = cortexkit_test_support::ScratchDir::new("display-write-failure");
    let path = scratch.path().join("display-records");
    let gauges = Arc::new(crate::event_publish::Gauges::default());
    let events = Arc::new(crate::event_publish::Publisher::with_display_directory(
        path.clone(),
        gauges.clone(),
    ));
    // A file in place of the directory makes writes fail even as root.
    std::fs::write(path, b"not a directory").unwrap();
    let bus = Arc::new(crate::event_publish::tests::Fake::default());
    events.connect(Arc::new(bus.clone()));
    let records = Arc::new(Records::with_events(events.clone()));
    let display = DisplayDouble::new(&["display"]);
    records.connect(display.clone());
    let deadlines = Arc::new(crate::egress::ConnectionDeadlines::default());
    deadlines.install_display(records.clone());
    records.arm(&frame(request()), &install(&planes())).unwrap();

    let body = json!({"outcome":"ok", "screen_text":"planted-screen-text"});
    let mut reply = frame(body.clone());
    reply.header.ty = FrameType::Response;
    let (tx, rx) = mpsc::channel(8);
    tx.send(reply).await.unwrap();
    drop(tx);
    let (sink, mut client) = tokio::io::duplex(4096);
    crate::egress::drain_writer(sink, rx, deadlines)
        .await
        .unwrap();
    let emitted = subc_transport::read_frame(&mut client)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&emitted.body).unwrap(),
        body
    );
    display.count(1).await;
    // Reads share the worker queue, so this resolves after the failed write.
    assert!(events
        .display_read(&"0".repeat(64))
        .await
        .unwrap()
        .is_none());
    crate::event_publish::tests::settle().await;
    assert!(bus.writes.lock().unwrap().is_empty());
    let mut metrics = serde_json::Map::new();
    gauges.insert_into(&mut metrics);
    assert_eq!(metrics["displayRecordDiskWriteFailures"], 1);
    assert_eq!(metrics["displayRecordsHeld"], 0);
}

#[tokio::test]
async fn no_identity_and_codemode_without_origin_or_pin_do_not_write() {
    let planes = planes();
    let facts = install(&planes);
    for request in [
        json!({"name":"browser_use","arguments":{"action":"status"}}),
        json!({"name":"computer_use","call_key":"basal:step","arguments":{"action":"read_state"}}),
        json!({"name":"browser_use","call_key":"pf:call","schema_pin":"provider-local-pin",
            "origin":{"carrier":{"kind":"reserved","module_id":"runner"},"call_key":"runner:missing-pin"},"arguments":{"action":"status"}}),
    ] {
        assert!(planes.routes.display.arm(&frame(request), &facts).is_none());
    }
    assert!(planes.routes.display.state.lock().unwrap().calls.is_empty());
}

#[tokio::test]
async fn direct_identity_is_the_attested_principal_and_own_pin() {
    let planes = planes();
    let display = DisplayDouble::new(&["display"]);
    planes.routes.display.connect(display.clone());
    let facts = install(&planes);
    let mut req = request();
    req.as_object_mut().unwrap().remove("origin");
    planes.routes.display.arm(&frame(req), &facts).unwrap();
    deliver(&planes, json!({"outcome":"ok"})).await;
    display.count(1).await;
    let writes = display.writes.lock().unwrap();
    assert_eq!(Some(&writes[0].runner), facts.principal.as_ref());
    assert_eq!(writes[0].call_key, "pf:local");
}

#[tokio::test]
async fn missing_or_ambiguous_display_drops_writes_without_changing_reply() {
    for modules in [vec![], vec!["one", "two"]] {
        let planes = planes();
        let display = DisplayDouble::new(&modules);
        planes.routes.display.connect(display.clone());
        let facts = install(&planes);
        planes
            .routes
            .display
            .arm(&frame(request()), &facts)
            .unwrap();
        deliver(&planes, json!({"outcome":"ok"})).await;
        tokio::task::yield_now().await;
        assert!(display.writes.lock().unwrap().is_empty());
    }
}

#[tokio::test(start_paused = true)]
async fn slow_or_failed_display_never_holds_the_reply() {
    for stall in [false, true] {
        let planes = planes();
        let display = Arc::new(DisplayDouble {
            modules: vec!["display".into()],
            writes: Mutex::new(vec![]),
            wrote: Notify::new(),
            stall,
            fail: true,
        });
        planes.routes.display.connect(display.clone());
        let facts = install(&planes);
        planes
            .routes
            .display
            .arm(&frame(request()), &facts)
            .unwrap();
        let now = tokio::time::Instant::now();
        deliver(&planes, json!({"outcome":"ok"})).await;
        assert_eq!(now.elapsed(), Duration::ZERO);
        tokio::task::yield_now().await;
        assert_eq!(display.writes.lock().unwrap().len(), 1);
        tokio::time::advance(WRITE_WINDOW + Duration::from_secs(1)).await;
        assert_eq!(display.writes.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn held_consent_decline_completes_once_even_if_settlement_races_flush() {
    use crate::journal::call_records::{Begin, ConsentEnding, ScopeIdentity};
    for settle_first in [false, true] {
        let planes = planes();
        let display = DisplayDouble::new(&["display"]);
        planes.routes.display.connect(display.clone());
        let facts = install(&planes);
        planes
            .routes
            .display
            .arm(&frame(request()), &facts)
            .unwrap();
        let principal = journal::call_records::principal_label(facts.principal.as_ref());
        let Begin::Execute(_) = planes.calls.begin_scoped(
            &principal,
            "pf:local",
            "display-test",
            Some(ScopeIdentity {
                owner: "reserved:owner".into(),
                reference: "scope".into(),
                scope_epoch: 1,
            }),
            1,
        ) else {
            panic!("admitted");
        };
        planes
            .calls
            .hold_consent(&principal, "pf:local", "ask", 2)
            .unwrap();
        if settle_first {
            planes
                .calls
                .finish_consent("ask", ConsentEnding::Denied, 3)
                .unwrap();
        }
        deliver(&planes, json!({"outcome":"consent_pending","ask_id":"ask"})).await;
        if !settle_first {
            planes
                .calls
                .finish_consent("ask", ConsentEnding::Denied, 3)
                .unwrap();
        }
        planes
            .calls
            .finish_consent("ask", ConsentEnding::Approved, 4)
            .unwrap();
        display.count(2).await;
        let writes = display.writes.lock().unwrap();
        assert_eq!(writes.len(), 2);
        let record = writes
            .iter()
            .find(|w| w.kind == DisplayKind::Record)
            .unwrap();
        let completion = writes
            .iter()
            .find(|w| w.kind == DisplayKind::Completion)
            .unwrap();
        assert_eq!(record.body["outcome"], "held");
        assert_eq!(record.body["reason"], "consent");
        assert_eq!(completion.body["outcome"], "error");
        assert_eq!(completion.body["reason"], "consent_declined");
        assert_eq!(record.call_key, completion.call_key);
        cortexkit_role_tool_display::schema::validate_completion(&completion.body, &schema())
            .unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn durations_exclude_queue_and_person_waits() {
    let planes = planes();
    let display = DisplayDouble::new(&["display"]);
    planes.routes.display.connect(display.clone());
    let facts = install(&planes);
    let timing = planes.routes.display.arm(&frame(request()), &facts);
    tokio::time::advance(Duration::from_millis(50)).await;
    ACTIVE
        .scope(timing, async {
            started();
            {
                let _queued = QueueWait::start();
                tokio::time::advance(Duration::from_millis(30)).await;
            }
            tokio::time::advance(Duration::from_millis(20)).await;
            {
                let _wait = PersonWait::start();
                tokio::time::advance(Duration::from_millis(100)).await;
            }
            deliver(&planes, json!({"outcome":"consent_pending"})).await;
        })
        .await;
    tokio::task::yield_now().await;
    let writes = display.writes.lock().unwrap();
    assert_eq!(writes[0].body["durationMs"], 20);
    assert_eq!(writes[0].body["heldMs"], 100);
    assert_eq!(writes[0].body["queuedMs"], 80);
}

#[tokio::test]
async fn planted_fixture_scanner_catches_secrets_then_excludes_them_from_records() {
    let planted = [
        "ck-planted-typed-secret",
        "ck-planted-page-text",
        "ck-planted-label",
        "ck-planted-cookie",
        "ck-planted-image-bytes",
    ];
    let scan =
        |bytes: &[u8], secret: &str| bytes.windows(secret.len()).any(|w| w == secret.as_bytes());
    let input = json!({"action":"navigate","url":"https://Example.COM/private/path?query=ck-planted-cookie#fragment",
        "text":planted[0],"page_text":planted[1],"label":planted[2],"secret":planted[3],"image":planted[4]});
    let input_bytes = serde_json::to_vec(&input).unwrap();
    for secret in planted {
        assert!(
            scan(&input_bytes, secret),
            "positive control must catch {secret}"
        );
    }
    let planes = planes();
    let display = DisplayDouble::new(&["display"]);
    planes.routes.display.connect(display.clone());
    let facts = install(&planes);
    let mut req = request();
    req["arguments"] = input;
    planes.routes.display.arm(&frame(req), &facts).unwrap();
    deliver(&planes, json!({"outcome":"ok","state_text":planted[1],"element_label":planted[2],"posts_returned":3,
        "url":"https://example.com/private/path?query=ck-planted-cookie#fragment","image":{"data":planted[4]}})).await;
    display.count(1).await;
    let writes = display.writes.lock().unwrap();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].body["site"], "https://example.com");
    assert_eq!(writes[0].body["postsReturned"], 3);
    let bytes = serde_json::to_vec(&*writes).unwrap();
    for secret in planted
        .into_iter()
        .chain(["/private/path", "?query=", "#fragment"])
    {
        assert!(!scan(&bytes, secret), "private content leaked: {secret}");
    }
    cortexkit_role_tool_display::schema::validate_record(&writes[0].body, &schema()).unwrap();
}

#[tokio::test]
async fn real_relayed_status_call_flushes_its_reply_before_display_work() {
    let planes = planes();
    let display = DisplayDouble::new(&["not-a-hardcoded-server-name"]);
    planes.routes.display.connect(display.clone());
    install(&planes);
    let (writer, receiver) = mpsc::channel(32);
    let (sink, mut client) = tokio::io::duplex(64 * 1024);
    let egress = tokio::spawn(crate::egress::drain_writer(
        sink,
        receiver,
        Arc::clone(&planes.egress_deadlines),
    ));
    handle_frame(frame(request()), &writer, &planes)
        .await
        .unwrap();
    // A hang guard, not a latency bound: the full library test suite can delay this
    // reply past a few seconds on a loaded machine.
    let response = tokio::time::timeout(
        crate::test_support::HANG_GUARD,
        subc_transport::read_frame(&mut client),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    assert_eq!(response.header.ty, FrameType::Response);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["outcome"], "no_session", "{body}");
    display.count(1).await;
    let writes = display.writes.lock().unwrap();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].call_key, "runner:call");
    drop(writes);
    egress.abort();
}

async fn bind_scope_carrier(
    planes: &Planes,
    principal: Principal,
    target: subc_protocol::RouteTarget,
    scope: Option<Value>,
) -> Frame {
    let request = json!({"op":"route.bind","route_channel":9,"epoch":1,"principal":principal,
        "identity":subc_protocol::BindIdentity::new("test", "display"), "target":target,"scope":scope});
    let mut request = frame(request);
    request.header.channel = 0;
    let (writer, mut replies) = mpsc::channel(8);
    handle_control_request(request, &writer, &planes.health, &planes.routes, None, None)
        .await
        .unwrap();
    replies.recv().await.unwrap()
}

async fn bind_display(planes: &Planes) -> Frame {
    bind_scope_carrier(
        planes,
        Principal::Reserved {
            module_id: "display-vendor".into(),
        },
        subc_protocol::RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
        None,
    )
    .await
}

#[tokio::test(start_paused = true)]
async fn declarer_cache_one_catalog_read_for_100_binds_within_ttl() {
    let planes = planes();
    let catalog = CatalogDouble::new(&["prefrontal-core"]);
    planes.routes.display.connect(catalog.clone());
    let stamp = subc_protocol::scope::ScopeStamp::new(
        Principal::Reserved {
            module_id: "scope-owner".into(),
        },
        "display-scope",
        1,
        subc_protocol::scope::ScopeKind::Head,
    );
    for _ in 0..100 {
        let reply = bind_scope_carrier(
            &planes,
            Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
            subc_protocol::RouteTarget::ToolProvider {
                module_id: "cerebellum".into(),
            },
            Some(serde_json::to_value(&stamp).unwrap()),
        )
        .await;
        assert_eq!(reply.header.ty, FrameType::Response);
    }
    assert_eq!(catalog.reads.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn declarer_cache_refreshes_at_30_seconds_and_expires_read_access() {
    let planes = planes();
    let catalog = CatalogDouble::new(&["display-vendor"]);
    planes.routes.display.connect(catalog.clone());
    assert_eq!(bind_display(&planes).await.header.ty, FrameType::Response);
    *catalog.answer.lock().unwrap() = Some(vec![]);
    tokio::time::advance(Duration::from_secs(29)).await;
    assert_eq!(bind_display(&planes).await.header.ty, FrameType::Response);
    let principal = Principal::Reserved {
        module_id: "display-vendor".into(),
    };
    let params = json!({"record_id":"missing"});
    let before = planes
        .routes
        .display
        .read(Some(&principal), params.clone())
        .await
        .unwrap_err();
    assert_ne!(
        before.code,
        cortexkit_role_tool_display::DISPLAY_READ_DENIED
    );
    assert_eq!(catalog.reads.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(bind_display(&planes).await.header.ty, FrameType::Error);
    let after = planes
        .routes
        .display
        .read(Some(&principal), params)
        .await
        .unwrap_err();
    assert_eq!(after.code, cortexkit_role_tool_display::DISPLAY_READ_DENIED);
    assert_eq!(catalog.reads.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn declarer_cache_caches_empty_and_ambiguous_answers() {
    for modules in [vec![], vec!["display-vendor", "another-display"]] {
        let planes = planes();
        let catalog = CatalogDouble::new(&modules);
        planes.routes.display.connect(catalog.clone());
        for _ in 0..100 {
            assert_eq!(bind_display(&planes).await.header.ty, FrameType::Error);
        }
        assert_eq!(catalog.reads.load(Ordering::SeqCst), 1);
    }
}

/// An absent module re-reads the catalog on its first bind, then at most once
/// per two seconds; an answer that names it is held for the full TTL.
#[tokio::test(start_paused = true)]
async fn declarer_cache_rereads_an_answer_missing_the_binder_at_most_every_two_seconds() {
    let planes = planes();
    let catalog = CatalogDouble::new(&[]);
    planes.routes.display.connect(catalog.clone());
    // A cold read that already leaves the binder out is not read again.
    assert_eq!(bind_display(&planes).await.header.ty, FrameType::Error);
    assert_eq!(catalog.reads.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_millis(500)).await;
    assert_eq!(bind_display(&planes).await.header.ty, FrameType::Error);
    assert_eq!(catalog.reads.load(Ordering::SeqCst), 2);
    *catalog.answer.lock().unwrap() = Some(vec!["display-vendor".into()]);
    tokio::time::advance(Duration::from_millis(1_999)).await;
    assert_eq!(bind_display(&planes).await.header.ty, FrameType::Error);
    assert_eq!(catalog.reads.load(Ordering::SeqCst), 2);
    tokio::time::advance(Duration::from_millis(1)).await;
    assert_eq!(bind_display(&planes).await.header.ty, FrameType::Response);
    assert_eq!(catalog.reads.load(Ordering::SeqCst), 3);
    // The fresh answer names the binder, so it is held for the full TTL again.
    *catalog.answer.lock().unwrap() = Some(vec![]);
    tokio::time::advance(Duration::from_secs(29)).await;
    assert_eq!(bind_display(&planes).await.header.ty, FrameType::Response);
    assert_eq!(catalog.reads.load(Ordering::SeqCst), 3);
}

/// Occipital's restart on 17 Nov: another module's bind cached an answer read
/// while the display module was away, and the display module bound a moment
/// later. Its first bind must read the catalog again rather than wait out the
/// answer's age.
#[tokio::test(start_paused = true)]
async fn declarer_cache_restarted_display_module_is_admitted_on_its_first_bind() {
    let planes = planes();
    let catalog = CatalogDouble::new(&[]);
    planes.routes.display.connect(catalog.clone());
    let other = bind_scope_carrier(
        &planes,
        Principal::Reserved {
            module_id: "basal".into(),
        },
        subc_protocol::RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
        None,
    )
    .await;
    assert_eq!(other.header.ty, FrameType::Error);
    assert_eq!(catalog.reads.load(Ordering::SeqCst), 1);
    *catalog.answer.lock().unwrap() = Some(vec!["display-vendor".into()]);
    tokio::time::advance(Duration::from_millis(100)).await;
    assert_eq!(bind_display(&planes).await.header.ty, FrameType::Response);
    assert_eq!(catalog.reads.load(Ordering::SeqCst), 2);
}

/// First-party binds are admitted without the display check, so however often
/// they bind, they never make cerebellum read the catalog again.
#[tokio::test(start_paused = true)]
async fn declarer_cache_first_party_binds_never_reread_the_catalog() {
    let planes = planes();
    let catalog = CatalogDouble::new(&[]);
    planes.routes.display.connect(catalog.clone());
    for _ in 0..20 {
        let reply = bind_scope_carrier(
            &planes,
            Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
            subc_protocol::RouteTarget::ToolProvider {
                module_id: "cerebellum".into(),
            },
            None,
        )
        .await;
        assert_eq!(reply.header.ty, FrameType::Response);
        tokio::time::advance(Duration::from_secs(5)).await;
    }
    assert_eq!(catalog.reads.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn declarer_cache_failed_read_is_not_cached() {
    let planes = planes();
    let catalog = CatalogDouble::new(&[]);
    *catalog.answer.lock().unwrap() = None;
    planes.routes.display.connect(catalog.clone());
    assert_eq!(bind_display(&planes).await.header.ty, FrameType::Error);
    assert_eq!(catalog.reads.load(Ordering::SeqCst), 1);
    *catalog.answer.lock().unwrap() = Some(vec!["display-vendor".into()]);
    assert_eq!(bind_display(&planes).await.header.ty, FrameType::Response);
    assert_eq!(catalog.reads.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn declarer_cache_concurrent_refresh_shares_success_failure_and_timeout() {
    for outcome in ["success", "failure", "timeout"] {
        let planes = planes();
        let catalog = CatalogDouble::new(&["display-vendor"]);
        planes.routes.display.connect(catalog.clone());
        assert_eq!(bind_display(&planes).await.header.ty, FrameType::Response);
        tokio::time::advance(Duration::from_secs(30)).await;
        catalog.blocked.store(true, Ordering::SeqCst);
        if outcome == "failure" {
            *catalog.answer.lock().unwrap() = None;
        }
        let mut binds: Vec<_> = (0..100).map(|_| Box::pin(bind_display(&planes))).collect();
        std::future::poll_fn(|cx| {
            for bind in &mut binds {
                assert!(std::future::Future::poll(bind.as_mut(), cx).is_pending());
            }
            std::task::Poll::Ready(())
        })
        .await;
        assert_eq!(catalog.reads.load(Ordering::SeqCst), 2, "{outcome}");
        if outcome == "timeout" {
            tokio::time::advance(WRITE_WINDOW).await;
        } else {
            catalog.release.add_permits(100);
        }
        let expected = if outcome == "success" {
            FrameType::Response
        } else {
            FrameType::Error
        };
        for bind in binds {
            assert_eq!(bind.await.header.ty, expected, "{outcome}");
        }
        assert_eq!(catalog.reads.load(Ordering::SeqCst), 2, "{outcome}");
        catalog.blocked.store(false, Ordering::SeqCst);
        *catalog.answer.lock().unwrap() = Some(vec!["display-vendor".into()]);
        assert_eq!(bind_display(&planes).await.header.ty, FrameType::Response);
        let expected_reads = if outcome == "success" { 2 } else { 3 };
        assert_eq!(catalog.reads.load(Ordering::SeqCst), expected_reads);
    }
}

#[tokio::test(start_paused = true)]
async fn declarer_cache_waiter_retries_when_refresh_owner_is_cancelled() {
    let records = Records::default();
    let catalog = CatalogDouble::new(&["display-vendor"]);
    catalog.blocked.store(true, Ordering::SeqCst);
    records.connect(catalog.clone());
    let mut owner = Box::pin(records.declarers());
    let mut waiter = Box::pin(records.declarers());
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(owner.as_mut(), cx).is_pending());
        assert!(std::future::Future::poll(waiter.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert_eq!(catalog.reads.load(Ordering::SeqCst), 1);
    drop(owner);
    catalog.blocked.store(false, Ordering::SeqCst);
    assert_eq!(waiter.await, vec!["display-vendor"]);
    assert_eq!(catalog.reads.load(Ordering::SeqCst), 2);
    assert_eq!(records.declarers().await, vec!["display-vendor"]);
    assert_eq!(catalog.reads.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_display_scope_carrier_cannot_call_any_operation() {
    let planes = planes();
    let display = DisplayDouble::new(&["prefrontal-core"]);
    planes.routes.display.connect(display);
    let principal = Principal::Reserved {
        module_id: "prefrontal-core".into(),
    };
    let stamp = subc_protocol::scope::ScopeStamp::new(
        Principal::Reserved {
            module_id: "scope-owner".into(),
        },
        "display-scope",
        1,
        subc_protocol::scope::ScopeKind::Head,
    );
    let bind = bind_scope_carrier(
        &planes,
        principal,
        subc_protocol::RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
        Some(serde_json::to_value(stamp).unwrap()),
    )
    .await;
    assert_eq!(bind.header.ty, FrameType::Response);
    for name in [
        "tool.catalog",
        "tool.views",
        "browser_use",
        "computer_use",
        "late_results",
        "some.read",
    ] {
        let mut request = frame(json!({"name":name,"arguments":{}}));
        request.header.channel = 9;
        let (writer, mut replies) = mpsc::channel(8);
        handle_route_request(request, &writer, &planes)
            .await
            .unwrap();
        let reply = replies.recv().await.unwrap();
        assert_eq!(reply.header.ty, FrameType::Error);
        assert!(String::from_utf8_lossy(&reply.body).contains(name));
    }
}

#[tokio::test]
async fn only_the_single_attested_display_can_read_catalog_and_views() {
    use subc_protocol::RouteTarget;
    let target = || RouteTarget::ToolProvider {
        module_id: "cerebellum".into(),
    };
    for modules in [
        vec![],
        vec!["display-vendor", "second-display"],
        vec!["display-vendor"],
    ] {
        for caller in ["display-vendor", "occipital", "unrelated"] {
            let planes = planes();
            planes.routes.display.connect(DisplayDouble::new(&modules));
            let bind = bind_scope_carrier(
                &planes,
                Principal::Reserved {
                    module_id: caller.into(),
                },
                target(),
                None,
            )
            .await;
            let admitted = modules.len() == 1 && modules[0] == caller;
            assert_eq!(
                bind.header.ty,
                if admitted {
                    FrameType::Response
                } else {
                    FrameType::Error
                },
                "{modules:?} {caller}"
            );
            for (name, arguments) in [
                ("tool.catalog", json!({})),
                ("tool.views", json!({"pins":["unpublished"]})),
            ] {
                let mut request = frame(json!({"name":name,"arguments":arguments}));
                request.header.channel = 9;
                let (writer, mut replies) = mpsc::channel(8);
                handle_route_request(request, &writer, &planes)
                    .await
                    .unwrap();
                let reply = replies.recv().await.unwrap();
                assert_eq!(
                    reply.header.ty,
                    if admitted {
                        FrameType::Response
                    } else {
                        FrameType::Error
                    },
                    "{caller}: {}",
                    String::from_utf8_lossy(&reply.body)
                );
                if admitted {
                    let body: Value = serde_json::from_slice(&reply.body).unwrap();
                    if name == "tool.views" {
                        assert_eq!(body, json!({"views":{"unpublished":"unknown"}}));
                    } else {
                        assert!(!body["tools"].as_array().unwrap().is_empty());
                    }
                }
            }
            if admitted {
                for name in [
                    "browser_use",
                    "computer_use",
                    "role.describe",
                    "late_results",
                    "late_results.ack",
                    "tool.withdraw",
                    "unknown.operation",
                ] {
                    let mut request = frame(json!({"name":name,"arguments":{"action":"status"}}));
                    request.header.channel = 9;
                    let (writer, mut replies) = mpsc::channel(8);
                    handle_route_request(request, &writer, &planes)
                        .await
                        .unwrap();
                    let reply = replies.recv().await.unwrap();
                    assert_eq!(reply.header.ty, FrameType::Error);
                    let body: Value = serde_json::from_slice(&reply.body).unwrap();
                    assert_eq!(body["code"], "principal_denied");
                    assert!(body["message"].as_str().unwrap().contains(name));
                }
            }
        }
    }
    let planes = planes();
    planes
        .routes
        .display
        .connect(DisplayDouble::new(&["display-vendor"]));
    let reserved = Principal::Reserved {
        module_id: "display-vendor".into(),
    };
    let bind = bind_scope_carrier(
        &planes,
        reserved,
        RouteTarget::ManagementSurface {
            module_id: "cerebellum".into(),
        },
        None,
    )
    .await;
    assert_eq!(bind.header.ty, FrameType::Response);
}

#[test]
fn catalog_discovery_ignores_readiness_and_non_display_capabilities() {
    let entry = |name: &str, provides: Vec<&str>, ready: bool| {
        serde_json::from_value::<subc_control::CatalogEntry>(json!({
        "module_id":name,"ready":ready,"roles":[],"control_ops":[],"capabilities":{"provides":provides,"requires":[],"must_never_reach":[]}
    })).unwrap()
    };
    let display = cortexkit_role_tool_display::TOOL_DISPLAY_CAPABILITY;
    assert_eq!(
        transport::declarers(&[entry("warming", vec![display], false)]),
        vec!["warming"]
    );
    assert!(transport::declarers(&[entry("app-only", vec!["app-server/v1"], true)]).is_empty());
    assert_eq!(
        transport::declarers(&[
            entry("one", vec![display], true),
            entry("two", vec![display], false)
        ])
        .len(),
        2
    );
}

#[tokio::test]
async fn consent_endings_do_not_turn_approval_into_a_failure() {
    use crate::journal::call_records::{Begin, ConsentEnding, ScopeIdentity};
    for durable in [false, true] {
        for settle_first in [false, true] {
            for (ending, reason) in [
                (ConsentEnding::Approved, None),
                (ConsentEnding::Denied, Some("consent_declined")),
                (ConsentEnding::Expired, Some("consent_expired")),
                (ConsentEnding::Withdrawn, Some("consent_withdrawn")),
            ] {
                let planes = planes();
                let display = DisplayDouble::new(&["display"]);
                planes.routes.display.connect(display.clone());
                let facts = install(&planes);
                planes
                    .routes
                    .display
                    .arm(&frame(request()), &facts)
                    .unwrap();
                if durable {
                    let principal =
                        journal::call_records::principal_label(facts.principal.as_ref());
                    let Begin::Execute(_) = planes.calls.begin_scoped(
                        &principal,
                        "pf:local",
                        "display-test",
                        Some(ScopeIdentity {
                            owner: "reserved:owner".into(),
                            reference: "scope".into(),
                            scope_epoch: 1,
                        }),
                        1,
                    ) else {
                        panic!("admitted");
                    };
                    planes
                        .calls
                        .hold_consent(&principal, "pf:local", "ask", 2)
                        .unwrap();
                }
                if settle_first {
                    planes.calls.finish_consent("ask", ending, 3).unwrap();
                }
                deliver(&planes, json!({"outcome":"consent_pending","ask_id":"ask"})).await;
                if !settle_first {
                    planes.calls.finish_consent("ask", ending, 3).unwrap();
                }
                display.count(if reason.is_some() { 2 } else { 1 }).await;
                tokio::task::yield_now().await;
                let writes = display.writes.lock().unwrap();
                assert_eq!(
                    writes.len(),
                    if reason.is_some() { 2 } else { 1 },
                    "{ending:?}, durable={durable}, settle_first={settle_first}"
                );
                let record = writes
                    .iter()
                    .find(|write| write.kind == DisplayKind::Record)
                    .unwrap();
                assert_eq!(record.body["outcome"], "held");
                assert_eq!(record.body["reason"], "consent");
                if let Some(reason) = reason {
                    let completion = writes
                        .iter()
                        .find(|write| write.kind == DisplayKind::Completion)
                        .unwrap();
                    assert_eq!(completion.body["outcome"], "error");
                    assert_eq!(completion.body["reason"], reason);
                }
                assert!(planes.routes.display.state.lock().unwrap().calls.is_empty());
            }
        }
    }
}

#[tokio::test]
async fn legacy_login_handoff_has_one_completion_without_changing_durable_state() {
    let planes = planes();
    let display = DisplayDouble::new(&["display"]);
    planes.routes.display.connect(display.clone());
    let facts = install(&planes);
    let timing = planes.routes.display.arm(&frame(request()), &facts);
    let settle = ACTIVE
        .scope(timing, async { handoff_settle().unwrap() })
        .await;
    deliver(&planes, json!({"outcome":"presented"})).await;
    assert!(settle(journal::call_records::HandoffEnding::LoginObserved));
    assert!(settle(journal::call_records::HandoffEnding::ClosedByCaller));
    display.count(2).await;
    let writes = display.writes.lock().unwrap();
    assert_eq!(writes.len(), 2);
    let record = writes
        .iter()
        .find(|w| w.kind == DisplayKind::Record)
        .unwrap();
    let completion = writes
        .iter()
        .find(|w| w.kind == DisplayKind::Completion)
        .unwrap();
    assert_eq!(record.body["reason"], "login_handoff");
    assert_eq!(completion.body["outcome"], "success");
    assert_eq!(planes.calls.record_count(), 0);
}

#[tokio::test]
async fn failed_reply_flush_never_starts_a_display_write() {
    let planes = planes();
    let bus = Arc::new(crate::event_publish::tests::Fake::default());
    planes.routes.display.events.connect(Arc::new(bus.clone()));
    let display = DisplayDouble::new(&["display"]);
    planes.routes.display.connect(display.clone());
    let facts = install(&planes);
    planes
        .routes
        .display
        .arm(&frame(request()), &facts)
        .unwrap();
    let mut reply = frame(json!({"outcome":"ok"}));
    reply.header.ty = FrameType::Response;
    let (tx, rx) = mpsc::channel(8);
    tx.send(reply).await.unwrap();
    drop(tx);
    let (sink, client) = tokio::io::duplex(1024);
    drop(client);
    assert!(
        crate::egress::drain_writer(sink, rx, Arc::clone(&planes.egress_deadlines))
            .await
            .is_err()
    );
    tokio::task::yield_now().await;
    assert!(display.writes.lock().unwrap().is_empty());
    assert!(bus.writes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn computer_record_uses_resolved_app_id_and_never_the_human_target_or_text() {
    const SECRET: &str = "planted.label";
    let scan = |bytes: &[u8]| bytes.windows(SECRET.len()).any(|w| w == SECRET.as_bytes());
    let mut request = request();
    request["name"] = json!("computer_use");
    request["arguments"] =
        json!({"action":"write_text","target":SECRET,"text":SECRET,"element_id":SECRET});
    let input = serde_json::to_vec(&request).unwrap();
    assert!(scan(&input), "positive scanner control");
    let planes = planes();
    let display = DisplayDouble::new(&["display"]);
    planes.routes.display.connect(display.clone());
    let facts = install(&planes);
    let timing = planes.routes.display.arm(&frame(request), &facts);
    ACTIVE.scope(timing, async {
        app("com.example.Editor");
        deliver(&planes, json!({"outcome":"completed","label":SECRET,"value":SECRET,"state_text":SECRET,"posts_returned":2})).await;
    }).await;
    display.count(1).await;
    let writes = display.writes.lock().unwrap();
    assert_eq!(writes[0].body["app"], "com.example.Editor");
    assert_eq!(writes[0].body["postsReturned"], 2);
    assert_eq!(writes[0].body["plane"], "computer");
    assert!(!scan(&serde_json::to_vec(&*writes).unwrap()));
    assert!(writes[0].body.values().all(|field| !field.is_array()));
    cortexkit_role_tool_display::schema::validate_record(&writes[0].body, &schema()).unwrap();
}

#[tokio::test]
async fn an_empty_array_drops_the_whole_record_or_completion_before_writing() {
    let records = Arc::new(Records::default());
    let display = DisplayDouble::new(&["display"]);
    records.connect(display.clone());
    for kind in [DisplayKind::Record, DisplayKind::Completion] {
        let body = json!({"durationMs":1,"outcome":"success","plane":"computer","app":[]})
            .as_object()
            .unwrap()
            .clone();
        assert!(
            cortexkit_role_tool_display::schema::validate_record(&body, &schema()).is_err(),
            "positive empty-array control"
        );
        records.spawn(DisplayWrite::new(
            Principal::Direct,
            "empty",
            kind,
            "pin",
            body,
        ));
    }
    tokio::task::yield_now().await;
    assert!(display.writes.lock().unwrap().is_empty());
    records.spawn(DisplayWrite::new(
        Principal::Direct,
        "scalar",
        DisplayKind::Record,
        "pin",
        json!({"durationMs":1,"outcome":"success","plane":"computer","app":"com.example.Editor"})
            .as_object()
            .unwrap()
            .clone(),
    ));
    display.count(1).await;
    let writes = display.writes.lock().unwrap();
    assert_eq!(writes.len(), 1);
    assert!(writes[0].body.values().all(|field| !field.is_array()));
}

#[tokio::test]
async fn seventy_thousand_ordinary_calls_write_records_with_bounded_tombstones() {
    let planes = planes();
    let display = DisplayDouble::new(&["display"]);
    planes.routes.display.connect(display.clone());
    let facts = install(&planes);
    let mut request = request();
    for index in 0..70_000 {
        request["call_key"] = json!(format!("local:{index}"));
        request["origin"]["call_key"] = json!(format!("runner:{index}"));
        assert!(
            planes
                .routes
                .display
                .arm(&frame(request.clone()), &facts)
                .is_some(),
            "call {index} lost tracking"
        );
        deliver(&planes, json!({"outcome":"ok"})).await;
        let state = planes.routes.display.state.lock().unwrap();
        assert!(
            state.identities.len() <= 65_536,
            "runner tombstones grew at call {index}"
        );
        assert!(
            state.seen_local_keys.len() <= 65_536,
            "local tombstones grew at call {index}"
        );
    }
    display.count(70_000).await;
    assert_eq!(display.writes.lock().unwrap().len(), 70_000);
    let state = planes.routes.display.state.lock().unwrap();
    assert!(state.calls.is_empty());
    let principal = journal::call_records::principal_label(facts.principal.as_ref());
    let runner = serde_json::to_string(&Principal::Reserved {
        module_id: "runner".into(),
    })
    .unwrap();
    assert_eq!(state.identities.len(), 65_536);
    assert_eq!(state.seen_local_keys.len(), 65_536);
    assert!(!state
        .identities
        .contains(&(runner.clone(), "runner:4463".into())));
    assert!(state.identities.contains(&(runner, "runner:4464".into())));
    assert!(!state
        .seen_local_keys
        .contains(&(principal.clone(), "local:4463".into())));
    assert!(state
        .seen_local_keys
        .contains(&(principal, "local:4464".into())));
}

#[tokio::test]
async fn an_active_call_remains_deduplicated_when_its_recent_tombstone_expires() {
    let planes = planes();
    let facts = install(&planes);
    let request = frame(request());
    assert!(planes.routes.display.arm(&request, &facts).is_some());
    {
        let mut state = planes.routes.display.state.lock().unwrap();
        state.identities.clear();
        state.seen_local_keys.clear();
    }
    assert!(planes.routes.display.arm(&request, &facts).is_none());
    assert_eq!(planes.routes.display.state.lock().unwrap().calls.len(), 1);
}

#[tokio::test]
async fn waiting_capacity_evicts_the_oldest_not_all_future_calls() {
    let planes = planes();
    let facts = install(&planes);
    let principal = journal::call_records::principal_label(facts.principal.as_ref());
    let mut request = request();
    for index in 0..16_386 {
        request["call_key"] = json!(format!("local:{index}"));
        request["origin"]["call_key"] = json!(format!("runner:{index}"));
        let mut request = frame(request.clone());
        request.header.corr = index;
        assert!(planes.routes.display.arm(&request, &facts).is_some());
    }
    let state = planes.routes.display.state.lock().unwrap();
    assert_eq!(state.calls.len(), 16_384);
    assert!(!state
        .calls
        .contains_key(&(principal.clone(), "local:0".into())));
    assert!(!state
        .calls
        .contains_key(&(principal.clone(), "local:1".into())));
    assert!(state
        .calls
        .contains_key(&(principal.clone(), "local:2".into())));
    assert!(state.calls.contains_key(&(principal, "local:16385".into())));
}

#[test]
fn error_reasons_preserve_real_outcome_codes_and_unknown_dispatch_is_not_success() {
    for code in [
        "screen_locked",
        "element_disabled",
        "denied",
        "cancelled",
        "not_started",
    ] {
        let body = json!({"outcome":code});
        assert_eq!(outcome(&body, false), ("error", Some(code)));
    }
    for code in [
        "dispatch_outcome_unknown",
        "effect_indeterminate",
        "delivery_unconfirmed",
        "indeterminate",
        "outcome_unknown",
    ] {
        let body = json!({"outcome":code});
        assert_eq!(outcome(&body, false), ("partial", Some("outcome_unknown")));
        assert_eq!(outcome(&body, true), ("partial", Some("outcome_unknown")));
        assert_eq!(
            outcome(&json!({"outcome":code,"isError":true}), false),
            ("partial", Some("outcome_unknown"))
        );
    }
    for code in ["ok", "completed", "captured", "login_observed", "timeout"] {
        assert!(crate::tool_result::is_success(code));
        assert_eq!(outcome(&json!({"outcome":code}), false), ("success", None));
    }
    for code in ["clicked", "typed", "read", "dispatched", "unchanged"] {
        assert!(!crate::tool_result::is_success(code));
        let body = json!({"outcome":code});
        assert_eq!(outcome(&body, false), ("error", Some(code)));
    }
    assert_eq!(
        outcome(&json!({"outcome":"private text with spaces"}), false),
        ("error", None)
    );
    assert_eq!(
        outcome(
            &json!({"code":"call_mode_unsupported","message":"private label"}),
            true
        ),
        ("error", Some("call_mode_unsupported"))
    );
}

#[tokio::test]
async fn finder_target_records_its_resolved_bundle_id_not_its_display_name() {
    use cerebellum_computer::app_state::source::RunningApp;
    use cerebellum_computer::capture::InMemoryCaptureBackend;
    let desk = computer_support::Desk::new(vec![]);
    desk.state().running = Some(vec![RunningApp {
        name: "Finder".into(),
        bundle_identity: "com.apple.finder".into(),
        pid: 101,
        frontmost: true,
    }]);
    let computer = computer_capability::ComputerPlane::<InMemoryCaptureBackend, _, _, _>::new(
        computer_support::audit(),
    )
    .with_app_state_source(desk.source());
    let planes = planes();
    let display = DisplayDouble::new(&["display"]);
    planes.routes.display.connect(display.clone());
    let facts = install(&planes);
    let mut request = request();
    request["name"] = json!("computer_use");
    request["arguments"] = json!({"action":"read_state","target":"Finder"});
    let target = request["arguments"]["target"].as_str().unwrap().to_owned();
    let timing = planes.routes.display.arm(&frame(request), &facts);
    ACTIVE
        .scope(timing, async {
            assert_eq!(
                computer.resolve_target_name(&target).await.unwrap(),
                "com.apple.finder"
            );
            deliver(&planes, json!({"outcome":"completed"})).await;
        })
        .await;
    display.count(1).await;
    let writes = display.writes.lock().unwrap();
    assert_eq!(writes[0].body["app"], "com.apple.finder");
    assert!(!serde_json::to_string(&writes[0].body)
        .unwrap()
        .contains("Finder"));
}

#[tokio::test]
async fn handoff_completions_report_the_true_ending_through_durable_and_legacy_paths() {
    use journal::call_records::{Begin, HandoffEnding, ScopeIdentity};
    for durable in [false, true] {
        for settle_first in [false, true] {
            for (ending, reason) in [
                (HandoffEnding::LoginObserved, None),
                (HandoffEnding::Captured, None),
                (HandoffEnding::HandoffExpired, Some("handoff_expired")),
                (HandoffEnding::Expired, Some("expired")),
                (HandoffEnding::ClosedByCaller, Some("closed_by_caller")),
                (HandoffEnding::SessionInvalid, Some("session_invalid")),
                (
                    HandoffEnding::HandoffInterrupted,
                    Some("handoff_interrupted"),
                ),
            ] {
                let planes = planes();
                let display = DisplayDouble::new(&["display"]);
                planes.routes.display.connect(display.clone());
                let facts = install(&planes);
                let timing = planes.routes.display.arm(&frame(request()), &facts);
                let principal = journal::call_records::principal_label(facts.principal.as_ref());
                if durable {
                    let scope = ScopeIdentity {
                        owner: "reserved:owner".into(),
                        reference: "scope".into(),
                        scope_epoch: 1,
                    };
                    let Begin::Execute(_) = planes.calls.begin_scoped(
                        &principal,
                        "pf:local",
                        "display-test",
                        Some(scope.clone()),
                        1,
                    ) else {
                        panic!("admitted");
                    };
                    planes
                        .calls
                        .hold_handoff(
                            &principal,
                            "pf:local",
                            "display-test",
                            scope,
                            "https://example.com",
                            2,
                        )
                        .unwrap();
                }
                let settle = ACTIVE
                    .scope(timing, async { handoff_settle().unwrap() })
                    .await;
                let finish = || {
                    if durable {
                        planes
                            .calls
                            .finish_handoff(&principal, "pf:local", ending, 3)
                            .unwrap();
                    } else {
                        assert!(settle(ending));
                    }
                };
                if settle_first {
                    finish();
                }
                deliver(&planes, json!({"outcome":"login_pending"})).await;
                if !settle_first {
                    finish();
                }
                finish();
                display.count(2).await;
                let writes = display.writes.lock().unwrap();
                assert_eq!(writes.len(), 2);
                let completion = writes
                    .iter()
                    .find(|write| write.kind == DisplayKind::Completion)
                    .unwrap();
                assert_eq!(
                    completion.body["outcome"],
                    if reason.is_some() { "error" } else { "success" },
                    "{ending:?}"
                );
                assert_eq!(
                    completion.body.get("reason").and_then(Value::as_str),
                    reason,
                    "{ending:?}"
                );
                assert!(planes.routes.display.state.lock().unwrap().calls.is_empty());
            }
        }
    }
}

#[tokio::test]
async fn scope_ended_completion_is_an_error_written_once_before_or_after_flush() {
    for settle_first in [false, true] {
        let planes = planes();
        let display = DisplayDouble::new(&["display"]);
        planes.routes.display.connect(display.clone());
        let facts = install(&planes);
        planes.routes.display.arm(&frame(request()), &facts);
        let principal = journal::call_records::principal_label(facts.principal.as_ref());
        let finish = || {
            planes.routes.display.completed(
                &principal,
                "pf:local",
                &json!({"outcome":"not_started","reason":"scope_ended"}),
            )
        };
        if settle_first {
            finish();
        }
        deliver(&planes, json!({"outcome":"login_pending"})).await;
        if !settle_first {
            finish();
        }
        finish();
        display.count(2).await;
        let writes = display.writes.lock().unwrap();
        assert_eq!(writes.len(), 2);
        let completion = writes
            .iter()
            .find(|write| write.kind == DisplayKind::Completion)
            .unwrap();
        assert_eq!(completion.body["outcome"], "error");
        assert_eq!(completion.body["reason"], "scope_ended");
    }
}

#[tokio::test]
async fn unconfirmed_fronting_restore_is_an_error_in_the_delivered_display_record() {
    let planes = planes();
    let display = DisplayDouble::new(&["display"]);
    planes.routes.display.connect(display.clone());
    let facts = install(&planes);
    let mut call = request();
    call["name"] = json!("computer_use");
    call["arguments"] =
        json!({"action":"keys", "target":"com.example.Editor", "keys":["command","a"]});
    planes.routes.display.arm(&frame(call), &facts).unwrap();
    let reply = cerebellum_computer::audit::FinalFrontingResult::new(json!({
        "outcome":"restore_failed", "effect_status":"not_dispatched",
        "fronting":{"fronted":false,"restore":"failed","purpose":"needs_front","mode":"background"}
    }))
    .into_value();
    deliver(&planes, reply).await;
    display.count(1).await;
    let writes = display.writes.lock().unwrap();
    assert_eq!(writes[0].body["outcome"], "error");
    assert_eq!(writes[0].body["reason"], "restore_failed");
    assert!(!serde_json::to_string(&writes[0].body)
        .unwrap()
        .contains("restored"));
    cortexkit_role_tool_display::schema::validate_record(&writes[0].body, &schema()).unwrap();
}

fn read_vector() -> Value {
    let (_, bytes) = cortexkit_role_tool_display::vectors::FILES
        .iter()
        .find(|(name, _)| *name == "reads.json")
        .unwrap();
    serde_json::from_str(bytes).unwrap()
}

/// A pull exactly as the display server sends it: the contract's named request
/// `{name: "display.read", arguments}`, not cerebellum's `{method, params}`.
async fn read_request(planes: &Planes, principal: Principal, params: Value) -> Frame {
    read_request_body(
        planes,
        principal,
        json!({"name":cortexkit_role_tool_display::DISPLAY_READ,"arguments":params}),
    )
    .await
}

async fn read_request_body(planes: &Planes, principal: Principal, body: Value) -> Frame {
    let facts = AcceptedBindFacts::from_bind(
        &subc_protocol::BindIdentity::new("test", "reader"),
        Some(principal),
        None,
        None,
        &subc_protocol::RouteTarget::ManagementSurface {
            module_id: "cerebellum".into(),
        },
    );
    planes.routes.insert(7, 1, facts);
    let (writer, mut replies) = mpsc::channel(8);
    handle_route_request(frame(body), &writer, planes)
        .await
        .unwrap();
    replies.recv().await.unwrap()
}

#[tokio::test]
async fn display_read_wire_vector_round_trips_through_management_and_fails_closed() {
    let vector = read_vector();
    let reserved = |module: &str| Principal::Reserved {
        module_id: module.into(),
    };
    for modules in [vec!["reader"], vec!["reader", "other"], vec![]] {
        for principal in [
            reserved("reader"),
            reserved("wrong"),
            Principal::Direct,
            Principal::Unverified,
        ] {
            let planes = planes();
            planes.routes.display.connect(DisplayDouble::new(&modules));
            let write: DisplayWrite = serde_json::from_value(vector["reply"].clone()).unwrap();
            planes
                .routes
                .display
                .events
                .seed_display("record:1", &write);
            // The vector's own request bytes, so the envelope can't drift from
            // the contract the display server follows.
            let reply =
                read_request_body(&planes, principal.clone(), vector["request"].clone()).await;
            let body: Value = serde_json::from_slice(&reply.body).unwrap();
            if modules == ["reader"] && principal == reserved("reader") {
                assert_eq!(reply.header.ty, FrameType::Response);
                assert_eq!(body, vector["reply"]);
                assert_eq!(
                    serde_json::to_value(serde_json::from_value::<DisplayWrite>(body).unwrap())
                        .unwrap(),
                    vector["reply"]
                );
            } else {
                assert_eq!(reply.header.ty, FrameType::Error);
                assert_eq!(body, vector["refusals"][0]);
            }
        }
    }
    let planes = planes();
    planes
        .routes
        .display
        .connect(DisplayDouble::new(&["reader"]));
    for (params, refusal) in [
        (json!({"record_id":"unknown"}), 1),
        (json!({"record_id":"bad id"}), 2),
    ] {
        let reply = read_request(&planes, reserved("reader"), params).await;
        assert_eq!(
            serde_json::from_slice::<Value>(&reply.body).unwrap(),
            vector["refusals"][refusal]
        );
    }
    planes.routes.display.events.unavailable_display();
    let reply = read_request(&planes, reserved("reader"), json!({"record_id":"record:1"})).await;
    assert_eq!(
        serde_json::from_slice::<Value>(&reply.body).unwrap(),
        vector["refusals"][3]
    );
}

#[tokio::test]
async fn display_read_also_answers_cerebellum_management_envelope() {
    let vector = read_vector();
    let planes = planes();
    planes
        .routes
        .display
        .connect(DisplayDouble::new(&["reader"]));
    let write: DisplayWrite = serde_json::from_value(vector["reply"].clone()).unwrap();
    planes
        .routes
        .display
        .events
        .seed_display("record:1", &write);
    let reader = || Principal::Reserved {
        module_id: "reader".into(),
    };
    let reply = read_request_body(
        &planes,
        reader(),
        json!({"method":cortexkit_role_tool_display::DISPLAY_READ,"params":vector["request"]["arguments"]}),
    )
    .await;
    assert_eq!(reply.header.ty, FrameType::Response);
    assert_eq!(
        serde_json::from_slice::<Value>(&reply.body).unwrap(),
        vector["reply"]
    );
}

#[tokio::test]
async fn display_read_catalog_failure_never_admits_by_default() {
    let planes = planes();
    let reply = read_request(
        &planes,
        Principal::Reserved {
            module_id: "reader".into(),
        },
        json!({"record_id":"x"}),
    )
    .await;
    assert_eq!(
        serde_json::from_slice::<Value>(&reply.body).unwrap()["code"],
        cortexkit_role_tool_display::DISPLAY_READ_DENIED
    );
}

#[tokio::test]
async fn full_display_map_drops_the_wake_but_keeps_direct_write() {
    let planes = planes();
    let display = DisplayDouble::new(&["display"]);
    planes.routes.display.connect(display.clone());
    let bus = Arc::new(crate::event_publish::tests::Fake::default());
    planes.routes.display.events.connect(Arc::new(bus.clone()));
    planes.routes.display.events.limit_display(0, 0);
    let facts = install(&planes);
    planes
        .routes
        .display
        .arm(&frame(request()), &facts)
        .unwrap();
    deliver(&planes, json!({"outcome":"ok"})).await;
    display.count(1).await;
    crate::event_publish::tests::settle().await;
    assert!(bus.writes.lock().unwrap().is_empty());
    assert_eq!(display.writes.lock().unwrap().len(), 1);
}
