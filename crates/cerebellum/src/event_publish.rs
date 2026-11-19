//! Best-effort bus notices and startup view publication. Call records, direct
//! display writes and tool.views remain authoritative when the bus is unavailable.

use std::{
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::{
        atomic::{
            AtomicBool, AtomicU64, AtomicU8,
            Ordering::{Acquire, Relaxed, Release},
        },
        Arc, Mutex, OnceLock,
    },
    time::Duration,
};

use cortexkit_role_tool_display::DisplayWrite;
use cortexkit_role_tool_provider::{
    late_result_ready_msg_id, late_result_ready_reader, LateResultReady, LATE_RESULT_READY_EVENT,
    LATE_RESULT_READY_VERSION,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tokio::{sync::mpsc, time::Instant};

mod late_result;
mod records;
pub(crate) use late_result::outcome as late_result_outcome;
#[cfg(test)]
pub(crate) mod tests;
#[cfg(not(test))]
mod transport;
mod views;

#[cfg(not(test))]
pub(crate) use transport::BusTransport;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
const CAPACITY: usize = 128;
const OPEN_WINDOW: Duration = Duration::from_secs(5);
const PUBLISH_WINDOW: Duration = Duration::from_secs(3);
const QUEUE_WINDOW: Duration = Duration::from_secs(10);
const LINGER: Duration = Duration::from_secs(30);

/// The transport builds subjects with `cortexkit-bus-naming` and the credential's
/// account. No account, session, or agent name is inferred at the commit hooks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    LateResultReady { custodian_module: Option<String> },
    DisplayRecordReady,
}

impl Kind {
    pub(crate) fn subject(&self, account: &str) -> Result<String, Failure> {
        let names = cortexkit_bus_naming::AccountNames::derive(account)
            .map_err(|_| Failure::Unavailable)?;
        let (event, version, reader) = self.parts();
        match reader {
            Some(reader) => names.event_subject_with_reader("cerebellum", event, version, reader),
            None => names.event_subject("cerebellum", event, version),
        }
        .map_err(|_| Failure::Unavailable)
    }

    fn parts(&self) -> (&'static str, u32, Option<&str>) {
        match self {
            Self::LateResultReady { custodian_module } => (
                LATE_RESULT_READY_EVENT,
                LATE_RESULT_READY_VERSION
                    .try_into()
                    .expect("late-result event version fits u32"),
                custodian_module.as_deref(),
            ),
            Self::DisplayRecordReady => (
                cortexkit_role_tool_display::DISPLAY_RECORD_READY_EVENT,
                cortexkit_role_tool_display::DISPLAY_RECORD_READY_VERSION
                    .try_into()
                    .expect("display event version fits u32"),
                None,
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Failure {
    Unavailable = 1,
    Timeout,
    Overflow,
    Expired,
    RecordCapacity,
}

pub(crate) trait Transport: Send + Sync {
    fn open(&self) -> BoxFuture<'_, Result<Box<dyn Connection>, Failure>>;
}

/// Dropping a connection must release all client owners and background work.
/// Success means the JetStream acknowledgement arrived, not just a socket write.
pub(crate) trait Connection: Send {
    fn views_bucket(&self) -> Result<Box<dyn views::Bucket>, Failure> {
        Err(Failure::Unavailable)
    }

    fn publish<'a>(
        &'a mut self,
        kind: &'a Kind,
        message_id: &'a str,
        bytes: &'a [u8],
    ) -> BoxFuture<'a, Result<(), Failure>>;
}

#[derive(Default)]
pub(crate) struct Gauges {
    published: AtomicU64,
    failed: AtomicU64,
    last_failure: AtomicU8,
    display_held: AtomicU64,
    display_disk_failures: AtomicU64,
    display_loaded: AtomicU64,
    display_damaged: AtomicU64,
}

static GAUGES: OnceLock<Arc<Gauges>> = OnceLock::new();

pub(crate) fn gauges() -> &'static Arc<Gauges> {
    GAUGES.get_or_init(|| Arc::new(Gauges::default()))
}

impl Gauges {
    fn failed(&self, reason: Failure) {
        self.last_failure.store(reason as u8, Relaxed);
        self.failed.fetch_add(1, Relaxed);
    }

    pub(crate) fn insert_into(&self, metrics: &mut Map<String, Value>) {
        metrics.insert(
            "busEventsPublished".into(),
            json!(self.published.load(Relaxed)),
        );
        metrics.insert("busEventsFailed".into(), json!(self.failed.load(Relaxed)));
        let reason = match self.last_failure.load(Relaxed) {
            1 => Some("unavailable"),
            2 => Some("timeout"),
            3 => Some("overflow"),
            4 => Some("expired"),
            5 => Some("record_capacity"),
            _ => None,
        };
        metrics.insert("busEventsLastFailureReason".into(), json!(reason));
        for (name, count) in [
            ("displayRecordsHeld", &self.display_held),
            (
                "displayRecordDiskWriteFailures",
                &self.display_disk_failures,
            ),
            ("displayRecordsLoadedAtStartup", &self.display_loaded),
            ("displayRecordDamagedFilesSkipped", &self.display_damaged),
        ] {
            metrics.insert(name.into(), json!(count.load(Relaxed)));
        }
    }
}

pub(crate) struct Publisher {
    sender: mpsc::Sender<Event>,
    receiver: Mutex<Option<mpsc::Receiver<Event>>>,
    transport_installed: AtomicBool,
    gauges: Arc<Gauges>,
    records: DisplayStore,
}

enum DisplayStore {
    Memory(Mutex<records::Records>),
    Disk(records::DiskWorker),
    Unavailable,
}

impl Default for Publisher {
    fn default() -> Self {
        Self::new(gauges().clone())
    }
}

struct Event {
    kind: Kind,
    message_id: String,
    bytes: Vec<u8>,
    queued_at: Instant,
}

fn identity(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

impl Publisher {
    pub(crate) fn production() -> Self {
        let gauges = Arc::clone(gauges());
        let Some(home) = cerebellum_core::platform_dirs::data_home() else {
            return Self::with_store(gauges, DisplayStore::Unavailable);
        };
        Self::with_display_directory(
            cerebellum_core::format_floor::module_directory(&home).join("display-records"),
            gauges,
        )
    }

    pub(crate) fn with_display_directory(directory: PathBuf, gauges: Arc<Gauges>) -> Self {
        let records = records::Records::open(directory, &gauges);
        Self::with_store(
            gauges,
            DisplayStore::Disk(records::DiskWorker::new(records)),
        )
    }

    fn new(gauges: Arc<Gauges>) -> Self {
        Self::with_store(gauges, DisplayStore::Memory(Mutex::default()))
    }

    fn with_store(gauges: Arc<Gauges>, records: DisplayStore) -> Self {
        let (sender, receiver) = mpsc::channel(CAPACITY);
        Self {
            sender,
            receiver: Mutex::new(Some(receiver)),
            transport_installed: AtomicBool::new(false),
            gauges,
            records,
        }
    }

    // Recovery can queue notices before installation, without a task or timer.
    #[cfg(test)]
    pub(crate) fn connect(&self, transport: Arc<dyn Transport>) {
        self.install(transport, false);
    }

    pub(crate) fn connect_and_reconcile(&self, transport: Arc<dyn Transport>) {
        self.install(transport, true);
    }

    fn install(&self, transport: Arc<dyn Transport>, reconcile_views: bool) {
        if let Some(receiver) = self.receiver.lock().unwrap().take() {
            tokio::spawn(run(
                transport,
                receiver,
                self.gauges.clone(),
                reconcile_views,
            ));
            self.transport_installed.store(true, Release);
        }
        if let DisplayStore::Disk(records) = &self.records {
            records.start(self.sender.clone(), self.gauges.clone());
        }
    }

    pub(crate) fn late_result(
        &self,
        principal: &str,
        call_key: &str,
        event_id: &str,
        outcome: &str,
    ) {
        let Some(reader) = late_result_ready_reader(principal) else {
            self.gauges.failed(Failure::Unavailable);
            return;
        };
        self.enqueue(
            Kind::LateResultReady {
                custodian_module: Some(reader.to_owned()),
            },
            late_result_ready_msg_id(event_id, reader),
            serde_json::to_vec(&LateResultReady::new(call_key, outcome))
                .expect("notice serializes"),
        );
    }

    pub(crate) fn tool_display(&self, write: &DisplayWrite) {
        let Some(id) = display_identity(write) else {
            return;
        };
        let bytes = serde_json::to_vec(write).expect("display write serializes");
        let publish = self.transport_installed.load(Acquire);
        match &self.records {
            DisplayStore::Memory(records) => {
                let mut records = records.lock().unwrap();
                let now = records.now();
                if records
                    .insert(id.clone(), bytes, now, &self.gauges)
                    .expect("memory store")
                {
                    if publish {
                        let pointer = display_pointer(&id);
                        self.enqueue(Kind::DisplayRecordReady, id, pointer);
                    }
                } else {
                    self.gauges.failed(Failure::RecordCapacity);
                }
            }
            DisplayStore::Disk(records) => {
                records.start(self.sender.clone(), self.gauges.clone());
                if let Err(reason) = records.store(id, bytes, publish) {
                    self.gauges.failed(reason);
                }
            }
            DisplayStore::Unavailable => {
                self.gauges.display_disk_failures.fetch_add(1, Relaxed);
                self.gauges.failed(Failure::Unavailable);
            }
        }
    }

    pub(crate) async fn display_read(&self, id: &str) -> Result<Option<Vec<u8>>, ()> {
        match &self.records {
            DisplayStore::Memory(records) => {
                let mut records = records.try_lock().map_err(|_| ())?;
                let now = records.now();
                records.read(id, now, &self.gauges).map_err(|_| ())
            }
            DisplayStore::Disk(records) => {
                records.start(self.sender.clone(), self.gauges.clone());
                records.read(id).await
            }
            DisplayStore::Unavailable => Err(()),
        }
    }

    #[cfg(test)]
    fn memory(&self) -> &Mutex<records::Records> {
        let DisplayStore::Memory(records) = &self.records else {
            panic!("test requires an isolated display store");
        };
        records
    }

    #[cfg(test)]
    pub(crate) fn seed_display(&self, id: &str, write: &DisplayWrite) {
        let mut records = self.memory().lock().unwrap();
        let now = records.now();
        assert!(records
            .insert(
                id.into(),
                serde_json::to_vec(write).unwrap(),
                now,
                &self.gauges
            )
            .unwrap());
    }

    #[cfg(test)]
    pub(crate) fn limit_display(&self, count: usize, bytes: usize) {
        *self.memory().lock().unwrap() = records::Records::with_limits(count, bytes);
    }

    #[cfg(test)]
    pub(crate) fn unavailable_display(&self) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = self.memory().lock().unwrap();
            panic!("simulate unavailable display map");
        }));
    }

    fn enqueue(&self, kind: Kind, message_id: String, bytes: Vec<u8>) {
        enqueue(&self.sender, &self.gauges, kind, message_id, bytes);
    }
}

fn enqueue(
    sender: &mpsc::Sender<Event>,
    gauges: &Gauges,
    kind: Kind,
    message_id: String,
    bytes: Vec<u8>,
) {
    let event = Event {
        kind,
        message_id,
        bytes,
        queued_at: Instant::now(),
    };
    if let Err(error) = sender.try_send(event) {
        gauges.failed(match error {
            mpsc::error::TrySendError::Full(_) => Failure::Overflow,
            mpsc::error::TrySendError::Closed(_) => Failure::Unavailable,
        });
    }
}

fn display_identity(write: &DisplayWrite) -> Option<String> {
    use cortexkit_role_tool_display::{
        DisplayLimits, MAX_COMPLETION_BYTES, MAX_DETAIL_BYTES, MAX_RECORD_BYTES,
    };
    let limits = DisplayLimits::new(MAX_RECORD_BYTES, MAX_DETAIL_BYTES, MAX_COMPLETION_BYTES, 0);
    cortexkit_role_tool_display::validate_write(write, &limits).ok()?;
    let writer = subc_protocol::Principal::Reserved {
        module_id: "cerebellum".into(),
    };
    let key = cortexkit_role_tool_display::idempotency_key(&writer, write)
        .expect("display identity serializes");
    Some(identity(&key))
}

fn display_pointer(record_id: &str) -> Vec<u8> {
    let ready = cortexkit_role_tool_display::DisplayRecordReady::new(record_id);
    debug_assert!(ready.validate().is_ok());
    serde_json::to_vec(&ready).expect("display pointer serializes")
}

async fn run(
    transport: Arc<dyn Transport>,
    mut events: mpsc::Receiver<Event>,
    gauges: Arc<Gauges>,
    reconcile_views: bool,
) {
    let mut connection: Option<Box<dyn Connection>> = None;
    let mut idle_close = None;
    if reconcile_views {
        match tokio::time::timeout(OPEN_WINDOW, transport.open()).await {
            Ok(Ok(opened)) => {
                let bucket = opened.views_bucket();
                connection = Some(opened);
                let reconcile = async {
                    let bucket = bucket?;
                    views::reconcile(
                        bucket.as_ref(),
                        crate::tool_provider::view_replies(),
                        &gauges,
                    )
                    .await;
                    Ok(())
                };
                match tokio::time::timeout(views::RECONCILE_WINDOW, reconcile).await {
                    Ok(Ok(())) => {}
                    Ok(Err(reason)) => gauges.failed(reason),
                    Err(_) => gauges.failed(Failure::Timeout),
                }
                // With no notices queued, close now so the bus client's credential
                // renewal task and the publisher's idle timer need not stay alive.
                if events.is_empty() {
                    connection = None;
                }
            }
            Ok(Err(reason)) => gauges.failed(reason),
            Err(_) => gauges.failed(Failure::Timeout),
        }
    }
    // Startup recovery may predate transport installation. Its queue budget
    // starts when delivery becomes possible, not while no client exists.
    let installed_at = Instant::now();
    loop {
        let event = tokio::select! {
            event = events.recv() => match event { Some(event) => event, None => break },
            _ = async {
                match idle_close {
                    Some(until) => tokio::time::sleep_until(until).await,
                    None => std::future::pending().await,
                }
            } => {
                connection = None;
                idle_close = None;
                continue;
            }
        };
        if idle_close.is_some_and(|until| until <= Instant::now()) {
            connection = None;
            idle_close = None;
        }
        let expires = event.queued_at.max(installed_at) + QUEUE_WINDOW;
        if expires <= Instant::now() {
            gauges.failed(Failure::Expired);
            continue;
        }
        if connection.is_none() {
            match tokio::time::timeout_at(
                expires.min(Instant::now() + OPEN_WINDOW),
                transport.open(),
            )
            .await
            {
                Ok(Ok(opened)) => connection = Some(opened),
                failure => {
                    gauges.failed(match failure {
                        Ok(Err(reason)) => reason,
                        _ => Failure::Timeout,
                    });
                    continue;
                }
            }
        }
        let bus = connection.as_mut().expect("opened connection");
        let result = tokio::time::timeout_at(
            expires.min(Instant::now() + PUBLISH_WINDOW),
            bus.publish(&event.kind, &event.message_id, &event.bytes),
        )
        .await;
        idle_close = Some(Instant::now() + LINGER);
        match result {
            Ok(Ok(())) => {
                gauges.published.fetch_add(1, Relaxed);
            }
            failure => {
                gauges.failed(match failure {
                    Ok(Err(reason)) => reason,
                    _ => Failure::Timeout,
                });
                connection = None;
                idle_close = None;
            }
        }
    }
}
