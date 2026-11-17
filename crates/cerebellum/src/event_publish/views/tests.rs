use std::collections::{BTreeMap, VecDeque};

use super::*;

#[derive(Clone, Default)]
struct FakeBucket {
    values: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    operations: Arc<Mutex<Vec<String>>>,
    dropped: Arc<AtomicBool>,
    watch_fails: bool,
    watch_hangs: bool,
    get_fails: bool,
}

struct FakeSnapshot {
    items: VecDeque<SnapshotItem>,
    dropped: Arc<AtomicBool>,
    hangs: bool,
}

impl Drop for FakeSnapshot {
    fn drop(&mut self) {
        self.dropped.store(true, Relaxed);
    }
}

impl Snapshot for FakeSnapshot {
    fn next(&mut self) -> BoxFuture<'_, Result<SnapshotItem, Failure>> {
        Box::pin(async move {
            if self.hangs {
                return std::future::pending().await;
            }
            Ok(self.items.pop_front().expect("no reads after CaughtUp"))
        })
    }
}

impl Bucket for FakeBucket {
    fn watch(&self) -> BoxFuture<'_, Result<Box<dyn Snapshot>, Failure>> {
        Box::pin(async move {
            if self.watch_fails {
                return Err(Failure::Unavailable);
            }
            let mut items: VecDeque<_> = self
                .values
                .lock()
                .unwrap()
                .keys()
                .cloned()
                .map(SnapshotItem::Key)
                .collect();
            items.push_back(SnapshotItem::CaughtUp);
            Ok(Box::new(FakeSnapshot {
                items,
                dropped: self.dropped.clone(),
                hangs: self.watch_hangs,
            }) as Box<dyn Snapshot>)
        })
    }

    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>, Failure>> {
        Box::pin(async move {
            assert!(self.watch_fails || self.dropped.load(Relaxed));
            self.operations.lock().unwrap().push(format!("get:{key}"));
            if self.get_fails {
                return Err(Failure::Unavailable);
            }
            Ok(self.values.lock().unwrap().get(key).cloned())
        })
    }

    fn put<'a>(&'a self, key: &'a str, bytes: &'a [u8]) -> BoxFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            self.operations.lock().unwrap().push(format!("put:{key}"));
            self.values
                .lock()
                .unwrap()
                .insert(key.into(), bytes.to_vec());
            Ok(())
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            self.operations
                .lock()
                .unwrap()
                .push(format!("delete:{key}"));
            self.values.lock().unwrap().remove(key);
            Ok(())
        })
    }
}

#[test]
fn keys_encode_the_whole_pin_not_a_shared_digest() {
    assert_eq!(key("tp1:a:abc:1"), "7470313a613a6162633a31");
    assert_eq!(key("tp1:b:abc:1"), "7470313a623a6162633a31");
    assert_ne!(key("tp1:a:abc:1"), key("tp1:b:abc:1"));
    assert_eq!(key("é"), "c3a9");
}

#[tokio::test]
async fn reconcile_only_writes_missing_or_changed_values_and_deletes_orphans() {
    let bucket = FakeBucket::default();
    let gauges = Gauges::default();
    let replies = vec![
        ("same".into(), vec![1]),
        ("changed".into(), vec![2]),
        ("missing".into(), vec![3]),
    ];
    bucket.values.lock().unwrap().extend([
        (key("same"), vec![1]),
        (key("changed"), vec![0]),
        ("orphan".into(), vec![4]),
    ]);
    reconcile(&bucket, replies, &gauges).await;
    assert!(bucket.dropped.load(Relaxed));
    assert_eq!(
        *bucket.operations.lock().unwrap(),
        [
            format!("get:{}", key("same")),
            format!("get:{}", key("changed")),
            format!("put:{}", key("changed")),
            format!("get:{}", key("missing")),
            format!("put:{}", key("missing")),
            "delete:orphan".into(),
        ]
    );
    assert_eq!(bucket.values.lock().unwrap().len(), 3);
    assert_eq!(gauges.published.load(Relaxed), 3);
    assert_eq!(gauges.failed.load(Relaxed), 0);
}

#[tokio::test(start_paused = true)]
async fn snapshot_deadline_drops_watch_skips_deletes_and_still_puts() {
    let bucket = FakeBucket {
        watch_hangs: true,
        ..Default::default()
    };
    bucket
        .values
        .lock()
        .unwrap()
        .insert("orphan".into(), vec![0]);
    let gauges = Gauges::default();
    let start = Instant::now();
    reconcile(&bucket, vec![("pin".into(), vec![1])], &gauges).await;
    assert_eq!(start.elapsed(), SNAPSHOT_WINDOW);
    assert!(bucket.dropped.load(Relaxed));
    assert_eq!(
        bucket.values.lock().unwrap().get(&key("pin")),
        Some(&vec![1])
    );
    assert!(bucket.values.lock().unwrap().contains_key("orphan"));
    assert_eq!(gauges.failed.load(Relaxed), 1);
    assert_eq!(gauges.last_failure.load(Relaxed), Failure::Timeout as u8);
}

#[tokio::test]
async fn snapshot_refusal_skips_deletes_and_still_puts() {
    let bucket = FakeBucket {
        watch_fails: true,
        ..Default::default()
    };
    bucket
        .values
        .lock()
        .unwrap()
        .insert("orphan".into(), vec![0]);
    let gauges = Gauges::default();
    reconcile(&bucket, vec![("pin".into(), vec![1])], &gauges).await;
    assert_eq!(
        bucket.values.lock().unwrap().get(&key("pin")),
        Some(&vec![1])
    );
    assert!(bucket.values.lock().unwrap().contains_key("orphan"));
    assert_eq!(gauges.failed.load(Relaxed), 1);
    assert_eq!(
        gauges.last_failure.load(Relaxed),
        Failure::Unavailable as u8
    );
}

#[tokio::test]
async fn oversized_view_is_skipped_and_counted_without_truncation_or_deletion() {
    let bucket = FakeBucket::default();
    bucket.values.lock().unwrap().insert(key("large"), vec![0]);
    let gauges = Gauges::default();
    reconcile(
        &bucket,
        vec![
            ("large".into(), vec![1; value_cap() + 1]),
            ("at-cap".into(), vec![2; value_cap()]),
        ],
        &gauges,
    )
    .await;
    assert_eq!(
        bucket.values.lock().unwrap().get(&key("large")),
        Some(&vec![0])
    );
    assert_eq!(
        bucket.values.lock().unwrap()[&key("at-cap")].len(),
        value_cap()
    );
    assert!(bucket
        .operations
        .lock()
        .unwrap()
        .iter()
        .all(|op| !op.ends_with(&key("large"))));
    assert_eq!(gauges.failed.load(Relaxed), 1);
    assert_eq!(gauges.last_failure.load(Relaxed), Failure::Overflow as u8);
}

struct StartupTransport {
    bucket: FakeBucket,
    opened: Arc<AtomicU64>,
    closed: Arc<AtomicU64>,
    published: Arc<AtomicU64>,
    hang_open: bool,
}

struct StartupConnection {
    bucket: FakeBucket,
    closed: Arc<AtomicU64>,
    published: Arc<AtomicU64>,
}

impl Drop for StartupConnection {
    fn drop(&mut self) {
        self.closed.fetch_add(1, Relaxed);
    }
}

impl Transport for StartupTransport {
    fn open(&self) -> BoxFuture<'_, Result<Box<dyn Connection>, Failure>> {
        Box::pin(async move {
            self.opened.fetch_add(1, Relaxed);
            if self.hang_open {
                return std::future::pending().await;
            }
            Ok(Box::new(StartupConnection {
                bucket: self.bucket.clone(),
                closed: self.closed.clone(),
                published: self.published.clone(),
            }) as Box<dyn Connection>)
        })
    }
}

impl Connection for StartupConnection {
    fn views_bucket(&self) -> Result<Box<dyn Bucket>, Failure> {
        Ok(Box::new(self.bucket.clone()))
    }

    fn publish<'a>(
        &'a mut self,
        _kind: &'a Kind,
        _message_id: &'a str,
        _bytes: &'a [u8],
    ) -> BoxFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            self.published.fetch_add(1, Relaxed);
            Ok(())
        })
    }
}

fn startup_transport(bucket: FakeBucket) -> Arc<StartupTransport> {
    Arc::new(StartupTransport {
        bucket,
        opened: Arc::new(AtomicU64::new(0)),
        closed: Arc::new(AtomicU64::new(0)),
        published: Arc::new(AtomicU64::new(0)),
        hang_open: false,
    })
}

#[tokio::test(start_paused = true)]
async fn startup_reconcile_closes_idle_connection_without_a_retry() {
    let transport = startup_transport(FakeBucket::default());
    let publisher = Publisher::new(Arc::new(Gauges::default()));
    publisher.connect_and_reconcile(transport.clone());
    assert_eq!(
        transport.opened.load(Relaxed),
        0,
        "startup never polls the bus"
    );
    super::super::tests::settle().await;
    assert_eq!(transport.opened.load(Relaxed), 1);
    assert_eq!(transport.closed.load(Relaxed), 1);
    assert_eq!(
        transport.bucket.values.lock().unwrap().len(),
        crate::tool_provider::view_replies().len()
    );
    tokio::time::advance(Duration::from_secs(3600)).await;
    super::super::tests::settle().await;
    assert_eq!(transport.opened.load(Relaxed), 1);
    assert_eq!(publisher.gauges.failed.load(Relaxed), 0);
}

#[tokio::test(start_paused = true)]
async fn startup_reconcile_reuses_connection_for_already_queued_notices() {
    let transport = startup_transport(FakeBucket::default());
    let publisher = Publisher::new(Arc::new(Gauges::default()));
    publisher.late_result("reserved:reader", "call", "settlement:1", "ok");
    publisher.connect_and_reconcile(transport.clone());
    super::super::tests::settle().await;
    assert_eq!(transport.opened.load(Relaxed), 1);
    assert_eq!(transport.published.load(Relaxed), 1);
    assert_eq!(transport.closed.load(Relaxed), 0);
    tokio::time::advance(LINGER).await;
    super::super::tests::settle().await;
    assert_eq!(transport.closed.load(Relaxed), 1);
}

#[tokio::test(start_paused = true)]
async fn bus_failure_does_not_block_startup_or_retry() {
    let mut transport = startup_transport(FakeBucket::default());
    Arc::get_mut(&mut transport).unwrap().hang_open = true;
    let publisher = Publisher::new(Arc::new(Gauges::default()));
    publisher.connect_and_reconcile(transport.clone());
    assert_eq!(transport.opened.load(Relaxed), 0);
    super::super::tests::settle().await;
    tokio::time::advance(OPEN_WINDOW).await;
    super::super::tests::settle().await;
    assert_eq!(publisher.gauges.failed.load(Relaxed), 1);
    assert_eq!(
        publisher.gauges.last_failure.load(Relaxed),
        Failure::Timeout as u8
    );
    tokio::time::advance(Duration::from_secs(3600)).await;
    super::super::tests::settle().await;
    assert_eq!(transport.opened.load(Relaxed), 1);
}

async fn handler_planes() -> crate::Planes {
    let planes = crate::Planes::with_browser_config_journaling(
        Arc::new(cerebellum_core::health::HealthState::new()),
        None,
        crate::JournalPersistence::Isolated,
    );
    let bind = json!({
        "op": "route.bind", "route_channel": 9, "epoch": 1,
        "principal": subc_protocol::Principal::Reserved { module_id: "prefrontal-core".into() },
        "identity": subc_protocol::BindIdentity::new("test", "views"),
        "target": subc_protocol::RouteTarget::ToolProvider { module_id: "cerebellum".into() },
    });
    let frame = subc_protocol::Frame::build(
        subc_protocol::FrameType::Request,
        crate::control_flags(),
        0,
        0,
        1,
        serde_json::to_vec(&bind).unwrap(),
    )
    .unwrap();
    let (writer, mut replies) = mpsc::channel(8);
    crate::handle_control_request(frame, &writer, &planes.health, &planes.routes, None, None)
        .await
        .unwrap();
    assert_eq!(
        replies.recv().await.unwrap().header.ty,
        subc_protocol::FrameType::Response
    );
    planes
}

async fn handler_reply(planes: &crate::Planes, pin: &str) -> Vec<u8> {
    let frame = subc_protocol::Frame::build(
        subc_protocol::FrameType::Request,
        crate::control_flags(),
        9,
        1,
        2,
        serde_json::to_vec(&json!({"name":"tool.views", "arguments":{"pins":[pin]}})).unwrap(),
    )
    .unwrap();
    let (writer, mut replies) = mpsc::channel(8);
    crate::handle_route_request(frame, &writer, planes)
        .await
        .unwrap();
    let reply = replies.recv().await.unwrap();
    assert_eq!(reply.header.ty, subc_protocol::FrameType::Response);
    reply.body.to_vec()
}

#[tokio::test]
async fn every_bucket_value_is_byte_equal_to_the_real_tool_views_handler() {
    let planes = handler_planes().await;
    let transport = startup_transport(FakeBucket::default());
    planes.calls.events.connect_and_reconcile(transport.clone());
    super::super::tests::settle().await;
    let replies = crate::tool_provider::view_replies();
    let legacy: BTreeMap<String, Value> = serde_json::from_str(include_str!(
        "../../../resources/tool-views/published-v1.json"
    ))
    .unwrap();
    assert!(legacy
        .keys()
        .all(|pin| replies.iter().any(|(served, _)| served == pin)));
    assert_eq!(transport.bucket.values.lock().unwrap().len(), replies.len());
    for (pin, _) in replies {
        let reply = handler_reply(&planes, &pin).await;
        assert!(reply.len() <= value_cap(), "{pin}: {} bytes", reply.len());
        assert_eq!(
            transport.bucket.values.lock().unwrap()[&key(&pin)],
            reply,
            "{pin}"
        );
    }
}

#[tokio::test]
async fn bus_refusal_does_not_change_tool_views_or_display_records() {
    let planes = handler_planes().await;
    let pin = crate::tool_provider::view_replies()[0].0.clone();
    let before = handler_reply(&planes, &pin).await;
    let transport = startup_transport(FakeBucket {
        watch_fails: true,
        get_fails: true,
        ..Default::default()
    });
    planes.calls.events.connect_and_reconcile(transport.clone());
    assert_eq!(transport.opened.load(Relaxed), 0);
    super::super::tests::settle().await;
    assert!(planes.calls.events.gauges.failed.load(Relaxed) > 0);
    assert_eq!(transport.closed.load(Relaxed), 1);
    assert_eq!(before, handler_reply(&planes, &pin).await);
    assert!(transport.bucket.values.lock().unwrap().is_empty());
    let write = cortexkit_role_tool_display::DisplayWrite::new(
        subc_protocol::Principal::Reserved {
            module_id: "prefrontal-core".into(),
        },
        "call",
        cortexkit_role_tool_display::DisplayKind::Record,
        pin,
        json!({"outcome":"success"}).as_object().unwrap().clone(),
    );
    planes.calls.events.tool_display(&write);
    assert_eq!(
        planes.calls.events.records.lock().unwrap().read(
            &identity(
                &cortexkit_role_tool_display::idempotency_key(
                    &subc_protocol::Principal::Reserved {
                        module_id: "cerebellum".into()
                    },
                    &write
                )
                .unwrap()
            ),
            Instant::now()
        ),
        Some(serde_json::to_vec(&write).unwrap())
    );
    super::super::tests::settle().await;
}
