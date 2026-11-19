use std::sync::atomic::AtomicBool;

use cortexkit_role_tool_display::DisplayKind;
use subc_protocol::Principal;

use super::*;

mod bus_names;
mod late_result_ready;

#[derive(Clone, Debug)]
pub(crate) struct Captured {
    pub(crate) kind: Kind,
    pub(crate) id: String,
    pub(crate) bytes: Vec<u8>,
}

#[derive(Default)]
pub(crate) struct Fake {
    pub(crate) writes: Mutex<Vec<Captured>>,
    opened: AtomicU64,
    closed: AtomicU64,
    pub(crate) fail_publish: AtomicBool,
    hang_open: AtomicBool,
    pub(crate) hang_publish: AtomicBool,
    pub(crate) readable: Mutex<Option<std::sync::Weak<Publisher>>>,
    wrote: tokio::sync::Notify,
}

struct FakeConnection(Arc<Fake>);

impl Drop for FakeConnection {
    fn drop(&mut self) {
        self.0.closed.fetch_add(1, Relaxed);
    }
}

impl Transport for Arc<Fake> {
    fn open(&self) -> BoxFuture<'_, Result<Box<dyn Connection>, Failure>> {
        Box::pin(async move {
            self.opened.fetch_add(1, Relaxed);
            if self.hang_open.load(Relaxed) {
                return std::future::pending().await;
            }
            Ok(Box::new(FakeConnection(self.clone())) as Box<dyn Connection>)
        })
    }
}

impl Connection for FakeConnection {
    fn publish<'a>(
        &'a mut self,
        kind: &'a Kind,
        message_id: &'a str,
        bytes: &'a [u8],
    ) -> BoxFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            if *kind == Kind::DisplayRecordReady {
                let publisher = self
                    .0
                    .readable
                    .lock()
                    .unwrap()
                    .as_ref()
                    .and_then(std::sync::Weak::upgrade);
                if let Some(publisher) = publisher {
                    assert!(
                        publisher.display_read(message_id).await.unwrap().is_some(),
                        "pointer must be readable before publish starts"
                    );
                }
            }
            self.0.writes.lock().unwrap().push(Captured {
                kind: kind.clone(),
                id: message_id.into(),
                bytes: bytes.into(),
            });
            self.0.wrote.notify_one();
            if self.0.hang_publish.load(Relaxed) {
                return std::future::pending().await;
            }
            if self.0.fail_publish.load(Relaxed) {
                Err(Failure::Unavailable)
            } else {
                Ok(())
            }
        })
    }
}

pub(crate) fn publisher() -> (Arc<Publisher>, Arc<Fake>) {
    let publisher = Arc::new(Publisher::new(Arc::new(Gauges::default())));
    let fake = Arc::new(Fake::default());
    *fake.readable.lock().unwrap() = Some(Arc::downgrade(&publisher));
    publisher.connect(Arc::new(fake.clone()));
    (publisher, fake)
}

pub(crate) async fn settle() {
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
}

fn write(kind: DisplayKind) -> DisplayWrite {
    DisplayWrite::new(
        Principal::Reserved {
            module_id: "thalamus-harness".into(),
        },
        "opaque:key",
        kind,
        "served-pin",
        json!({"outcome":"success", "plane":"browser", "action":"status", "durationMs":12, "queuedMs":0})
            .as_object().unwrap().clone(),
    )
}

#[tokio::test]
async fn announced_display_record_remains_readable_after_restart() {
    let directory = cortexkit_test_support::ScratchDir::new("cerebellum-display-restart");
    let path = directory.path().join("display-records");
    let notice = {
        let publisher = Publisher::with_display_directory(path.clone(), Arc::default());
        let bus = Arc::new(Fake::default());
        publisher.connect(Arc::new(bus.clone()));
        publisher.tool_display(&write(DisplayKind::Record));
        tokio::time::timeout(crate::test_support::HANG_GUARD, bus.wrote.notified())
            .await
            .expect("durable write and bus publication finished");
        let published = bus.writes.lock().unwrap();
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].kind, Kind::DisplayRecordReady);
        let pointer: Value = serde_json::from_slice(&published[0].bytes).unwrap();
        pointer["record_id"].as_str().unwrap().to_owned()
    };

    let restarted = Publisher::with_display_directory(path, Arc::default());
    assert_eq!(
        restarted.display_read(&notice).await.unwrap(),
        Some(serde_json::to_vec(&write(DisplayKind::Record)).unwrap()),
        "a record the bus announced must survive a restart without the writer or bus"
    );
    assert_eq!(restarted.gauges.display_loaded.load(Relaxed), 1);
}

#[test]
fn bus_notice_disabled_display_does_not_queue_but_recovered_late_result_does() {
    use crate::journal::call_records::{
        Begin, CallRecords, InMemoryCallRecordStorage, ScopeIdentity,
    };

    let publisher = Publisher::new(Arc::new(Gauges::default()));
    for _ in 0..200 {
        publisher.tool_display(&write(DisplayKind::Record));
    }
    assert_eq!(publisher.gauges.failed.load(Relaxed), 0);
    assert_eq!(publisher.sender.capacity(), CAPACITY);
    assert!(matches!(
        publisher
            .receiver
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));

    let storage = InMemoryCallRecordStorage::new();
    let calls = CallRecords::open(Box::new(storage.clone()), 100);
    let owner = "reserved:prefrontal-core";
    assert!(matches!(
        calls.begin(owner, "opaque:recovered", "scope", 100),
        Begin::Execute(_)
    ));
    calls
        .hold_handoff(
            owner,
            "opaque:recovered",
            "handoff",
            ScopeIdentity {
                owner: owner.into(),
                reference: "scope".into(),
                scope_epoch: 1,
            },
            "https://login.example",
            100,
        )
        .unwrap();
    drop(calls);
    let recovered = CallRecords::open(Box::new(storage), 101);
    for _ in 0..200 {
        recovered.events.tool_display(&write(DisplayKind::Record));
    }
    assert_eq!(recovered.events.sender.capacity(), CAPACITY - 1);
    let queued = recovered
        .events
        .receiver
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .try_recv()
        .unwrap();
    assert_eq!(
        queued.kind,
        Kind::LateResultReady {
            custodian_module: Some("prefrontal-core".into())
        }
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&queued.bytes).unwrap(),
        json!({"call_key":"opaque:recovered", "outcome":"handoff_interrupted"})
    );
    assert_eq!(recovered.events.sender.capacity(), CAPACITY);
    let late = recovered
        .late_results(
            owner,
            &cortexkit_role_tool_provider::late_results::LateResultsRequest::new(),
            101,
        )
        .unwrap();
    assert_eq!(
        queued.message_id,
        format!("{}:prefrontal-core", late.entries[0].event_id)
    );
}

#[test]
fn custodian_tail_requires_exact_reserved_module_label() {
    for module in ["thalamus-harness", "prefrontal-core", "broca"] {
        assert_eq!(
            late_result_ready_reader(&format!("reserved:{module}")),
            Some(module)
        );
    }
    for label in [
        "xreserved:broca",
        "reserved:broca:extra",
        "Reserved:broca",
        "reserved:Broca",
        " reserved:broca",
        "reserved:broca ",
        "reserved: broca",
        "reserved:",
        "mcp:broca",
        "mcp:reserved:broca",
        "direct",
        "unverified",
        "absent",
        "reserved:broca.*",
        "reserved:broca.>",
    ] {
        assert_eq!(late_result_ready_reader(label), None, "{label:?}");
    }
}

#[tokio::test]
async fn bus_notice_bodies_and_ids_are_narrow_and_stable() {
    let (publisher, fake) = publisher();
    publisher.late_result("reserved:broca", "opaque:key", "settlement:1", "ok");
    publisher.late_result("reserved:broca", "opaque:key", "settlement:1", "ok");
    publisher.late_result("reserved:broca", "opaque:key", "settlement:2", "ok");
    let record = write(DisplayKind::Record);
    publisher.tool_display(&record);
    let mut changed = record.clone();
    changed.schema_pin = "different-pin".into();
    changed.body.insert("durationMs".into(), json!(88));
    publisher.tool_display(&changed);
    publisher.tool_display(&write(DisplayKind::Completion));
    settle().await;
    let writes = fake.writes.lock().unwrap().clone();
    assert_eq!(writes.len(), 6);
    assert_eq!(
        writes[0].kind,
        Kind::LateResultReady {
            custodian_module: Some("broca".into())
        }
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&writes[0].bytes).unwrap(),
        json!({"call_key":"opaque:key", "outcome":"ok"})
    );
    assert_eq!(writes[0].id, writes[1].id);
    assert_ne!(writes[0].id, writes[2].id);
    assert_eq!(writes[3].kind, Kind::DisplayRecordReady);
    assert_eq!(
        serde_json::from_slice::<Value>(&writes[3].bytes).unwrap(),
        json!({"record_id": writes[3].id})
    );
    let pointer: cortexkit_role_tool_display::DisplayRecordReady =
        serde_json::from_slice(&writes[3].bytes).unwrap();
    pointer.validate().unwrap();
    assert_eq!(
        publisher
            .display_read(&writes[3].id)
            .await
            .unwrap()
            .unwrap(),
        serde_json::to_vec(&changed).unwrap()
    );
    assert_eq!(
        writes[3].kind.subject("test").unwrap(),
        "ck.test.event.cerebellum.display_record_ready.v1"
    );
    assert_eq!(
        writes[0].kind.subject("test").unwrap(),
        "ck.test.event.cerebellum.late_result_ready.v1.broca"
    );
    assert_eq!(
        writes[3].id, writes[4].id,
        "display identity excludes body and schema pin"
    );
    assert_ne!(
        writes[3].id, writes[5].id,
        "completion has its own identity"
    );
    assert_eq!(publisher.gauges.published.load(Relaxed), 6);
}

#[tokio::test(start_paused = true)]
async fn bus_notice_idle_close_is_thirty_seconds_after_last_publish() {
    let (publisher, fake) = publisher();
    settle().await;
    tokio::time::advance(Duration::from_secs(300)).await;
    assert_eq!(
        fake.opened.load(Relaxed),
        0,
        "idle publisher must not connect"
    );
    publisher.late_result("reserved:broca", "first", "settlement:1", "declined");
    settle().await;
    tokio::time::advance(Duration::from_secs(29)).await;
    settle().await;
    assert_eq!(fake.closed.load(Relaxed), 0);
    publisher.tool_display(&write(DisplayKind::Record));
    settle().await;
    assert_eq!(
        fake.opened.load(Relaxed),
        1,
        "both events share one connection"
    );
    tokio::time::advance(Duration::from_secs(29)).await;
    settle().await;
    assert_eq!(fake.closed.load(Relaxed), 0);
    tokio::time::advance(Duration::from_secs(1)).await;
    settle().await;
    assert_eq!(fake.closed.load(Relaxed), 1);
    tokio::time::advance(Duration::from_secs(300)).await;
    settle().await;
    assert_eq!(
        fake.opened.load(Relaxed),
        1,
        "idle close must not start a reconnect timer"
    );
    publisher.late_result("reserved:broca", "second", "settlement:2", "declined");
    settle().await;
    assert_eq!(fake.opened.load(Relaxed), 2);
}

#[tokio::test(start_paused = true)]
async fn bus_notice_waits_are_bounded_and_overflow_never_blocks() {
    let (publisher, fake) = publisher();
    fake.hang_publish.store(true, Relaxed);
    publisher.late_result("reserved:reader", "first", "settlement:1", "declined");
    settle().await;
    for _ in 0..CAPACITY {
        publisher.late_result("reserved:reader", "queued", "settlement:2", "declined");
    }
    publisher.late_result("reserved:reader", "dropped", "settlement:3", "declined");
    assert_eq!(publisher.gauges.failed.load(Relaxed), 1);
    assert_eq!(
        publisher.gauges.last_failure.load(Relaxed),
        Failure::Overflow as u8
    );
    tokio::time::advance(PUBLISH_WINDOW).await;
    settle().await;
    assert_eq!(
        fake.closed.load(Relaxed),
        1,
        "timed-out publish drops the connection"
    );
    assert_eq!(
        publisher.gauges.last_failure.load(Relaxed),
        Failure::Timeout as u8
    );
    // Advancing beyond the queue deadline drops all stale notices without
    // spending one connection deadline on every queued item.
    tokio::time::advance(QUEUE_WINDOW).await;
    settle().await;
    assert_eq!(
        publisher.gauges.last_failure.load(Relaxed),
        Failure::Expired as u8
    );
    assert!(fake.opened.load(Relaxed) < 4);

    let (publisher, fake) = self::publisher();
    fake.hang_open.store(true, Relaxed);
    publisher.late_result("reserved:reader", "open", "settlement:4", "declined");
    settle().await;
    tokio::time::advance(OPEN_WINDOW).await;
    settle().await;
    assert_eq!(publisher.gauges.failed.load(Relaxed), 1);
    assert_eq!(
        publisher.gauges.last_failure.load(Relaxed),
        Failure::Timeout as u8
    );
    assert!(fake.writes.lock().unwrap().is_empty());
}

#[test]
fn bus_notice_health_is_counts_and_reason_words_only() {
    let gauges = Gauges::default();
    let mut metrics = Map::new();
    gauges.insert_into(&mut metrics);
    assert_eq!(metrics["busEventsLastFailureReason"], Value::Null);
    gauges.failed(Failure::Unavailable);
    gauges.insert_into(&mut metrics);
    assert_eq!(metrics, json!({"busEventsPublished":0, "busEventsFailed":1, "busEventsLastFailureReason":"unavailable",
        "displayRecordsHeld":0, "displayRecordDiskWriteFailures":0, "displayRecordsLoadedAtStartup":0, "displayRecordDamagedFilesSkipped":0
    }).as_object().unwrap().clone());
}

#[tokio::test]
async fn record_capacity_drops_only_the_new_pointer_and_counts_its_reason() {
    let (publisher, fake) = publisher();
    publisher.limit_display(1, 32 * 1024);
    publisher.tool_display(&write(DisplayKind::Record));
    publisher.tool_display(&write(DisplayKind::Completion));
    settle().await;
    assert_eq!(fake.writes.lock().unwrap().len(), 1);
    let mut metrics = Map::new();
    publisher.gauges.insert_into(&mut metrics);
    assert_eq!(metrics["busEventsLastFailureReason"], "record_capacity");
    assert_eq!(metrics["busEventsFailed"], 1);
}
