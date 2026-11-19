use tokio::sync::oneshot;

use super::*;

// Only this worker touches the disk store after startup. A bounded queue keeps
// a slow filesystem from holding egress or the separate bus publisher.
pub(in crate::event_publish) struct DiskWorker {
    commands: mpsc::Sender<Command>,
    pending: Mutex<Option<(Records, mpsc::Receiver<Command>)>>,
}

enum Command {
    Store {
        id: String,
        bytes: Vec<u8>,
        publish: bool,
    },
    Read {
        id: String,
        reply: oneshot::Sender<Result<Option<Vec<u8>>, ()>>,
    },
}

impl DiskWorker {
    pub(in crate::event_publish) fn new(records: Records) -> Self {
        let (commands, receiver) = mpsc::channel(CAPACITY);
        Self {
            commands,
            pending: Mutex::new(Some((records, receiver))),
        }
    }

    pub(in crate::event_publish) fn start(&self, sender: mpsc::Sender<Event>, gauges: Arc<Gauges>) {
        if let Some((records, receiver)) = self.pending.lock().unwrap().take() {
            tokio::spawn(run(records, receiver, sender, gauges));
        }
    }

    pub(in crate::event_publish) fn store(
        &self,
        id: String,
        bytes: Vec<u8>,
        publish: bool,
    ) -> Result<(), Failure> {
        self.commands
            .try_send(Command::Store { id, bytes, publish })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => Failure::Overflow,
                mpsc::error::TrySendError::Closed(_) => Failure::Unavailable,
            })
    }

    pub(in crate::event_publish) async fn read(&self, id: &str) -> Result<Option<Vec<u8>>, ()> {
        let (reply, receiver) = oneshot::channel();
        self.commands
            .try_send(Command::Read {
                id: id.to_owned(),
                reply,
            })
            .map_err(|_| ())?;
        receiver.await.map_err(|_| ())?
    }
}

async fn run(
    mut records: Records,
    mut commands: mpsc::Receiver<Command>,
    sender: mpsc::Sender<Event>,
    gauges: Arc<Gauges>,
) {
    let mut retry_expiry = None;
    loop {
        let command = tokio::select! {
            command = commands.recv() => match command {
                Some(command) => Some(command),
                None => break,
            },
            _ = async {
                match records.next_deadline() {
                    Some(deadline) => {
                        let until = Instant::now() + Duration::from_millis(deadline.saturating_sub(records.now()));
                        tokio::time::sleep_until(retry_expiry.map_or(until, |retry| until.max(retry))).await;
                    }
                    None => std::future::pending::<()>().await,
                }
            } => None,
        };
        let now = records.now();
        let metrics = gauges.clone();
        let work = tokio::task::spawn_blocking(move || {
            let mut notice = None;
            let expiry_failed = match command {
                Some(Command::Store { id, bytes, publish }) => {
                    match records.insert(id.clone(), bytes, now, &metrics) {
                        Ok(true) => {
                            notice = publish.then_some(id);
                            false
                        }
                        Ok(false) => {
                            metrics.display_dropped_full();
                            false
                        }
                        Err(_) => {
                            metrics.display_disk_failures.fetch_add(1, Relaxed);
                            metrics.failed(Failure::Unavailable);
                            true
                        }
                    }
                }
                Some(Command::Read { id, reply }) => {
                    if !reply.is_closed() {
                        let answer = records.read(&id, now, &metrics).map_err(|_| {
                            metrics.display_disk_failures.fetch_add(1, Relaxed);
                        });
                        let _ = reply.send(answer);
                    }
                    // If a deletion failed, the timer retries it with backoff.
                    false
                }
                None => records.expire(now, &metrics).is_err_and(|_| {
                    metrics.display_disk_failures.fetch_add(1, Relaxed);
                    true
                }),
            };
            (records, expiry_failed, notice)
        });
        match work.await {
            Ok((updated, failed, notice)) => {
                records = updated;
                if let Some(id) = notice {
                    let pointer = display_pointer(&id);
                    enqueue(&sender, &gauges, Kind::DisplayRecordReady, id, pointer);
                }
                if failed
                    && records
                        .next_deadline()
                        .is_some_and(|deadline| deadline <= now)
                {
                    retry_expiry = Some(Instant::now() + Duration::from_secs(60));
                } else if records
                    .next_deadline()
                    .is_none_or(|deadline| deadline > now)
                {
                    retry_expiry = None;
                }
            }
            Err(_) => {
                gauges.display_disk_failures.fetch_add(1, Relaxed);
                break;
            }
        }
    }
}
