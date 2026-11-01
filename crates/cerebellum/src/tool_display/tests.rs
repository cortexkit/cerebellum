use super::*;
use crate::*;
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
        tokio::time::timeout(Duration::from_secs(2), async {
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
    let response = tokio::time::timeout(
        Duration::from_secs(2),
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
async fn twenty_thousand_ordinary_calls_each_write_a_record_and_release_tracking() {
    let planes = planes();
    let display = DisplayDouble::new(&["display"]);
    planes.routes.display.connect(display.clone());
    let facts = install(&planes);
    let mut request = request();
    for index in 0..20_000 {
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
    }
    display.count(20_000).await;
    assert_eq!(display.writes.lock().unwrap().len(), 20_000);
    assert!(planes.routes.display.state.lock().unwrap().calls.is_empty());
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
