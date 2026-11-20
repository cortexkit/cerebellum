//! Request delivery deadlines and bounded write-and-flush batches.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use subc_protocol::{Frame, FrameType};
use tokio::io::{AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;

use crate::budgets::EGRESS_SEND_MS;
use crate::{write_frame, ModuleError, EGRESS_BUFFER};

pub(crate) type RequestId = (u16, u32, u64);

pub(crate) fn request_id(frame: &Frame) -> RequestId {
    (frame.header.channel, frame.header.epoch, frame.header.corr)
}

#[derive(Default)]
pub(crate) struct ConnectionDeadlines {
    pub(crate) pending:
        std::sync::Mutex<std::collections::BTreeMap<RequestId, tokio::time::Instant>>,
    pub(crate) changed: tokio::sync::Notify,
    display: OnceLock<Arc<crate::tool_display::Records>>,
}

impl ConnectionDeadlines {
    /// Start the writer for HELLO before the planes exist. Install their
    /// display records before dispatch can arm its first tool reply.
    pub(crate) fn install_display(&self, display: Arc<crate::tool_display::Records>) {
        assert!(
            self.display.set(display).is_ok(),
            "display records already installed"
        );
    }

    pub(crate) fn arm(&self, request: RequestId, end: tokio::time::Instant) {
        self.pending.lock().unwrap().entry(request).or_insert(end);
        self.changed.notify_waiters();
    }

    pub(crate) fn delivered(&self, requests: &[RequestId]) {
        let mut pending = self.pending.lock().unwrap();
        for request in requests {
            pending.remove(request);
        }
        self.changed.notify_waiters();
    }

    /// Resolve once no terminal reply is owed on this connection.
    pub(crate) async fn settled(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.pending.lock().unwrap().is_empty() {
                return;
            }
            changed.await;
        }
    }

    pub(crate) async fn expired(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let end = self.pending.lock().unwrap().values().copied().min();
            match end {
                Some(end) => tokio::select! {
                    biased;
                    _ = tokio::time::sleep_until(end) => {
                        // A flush ready at the same clock tick must get one
                        // poll before its delivery acknowledgement is checked.
                        tokio::task::yield_now().await;
                        if self.pending.lock().unwrap().values().any(|end| *end <= tokio::time::Instant::now()) {
                            return;
                        }
                    },
                    _ = changed => {},
                },
                None => changed.await,
            }
        }
    }
}

#[cfg(test)]
pub(crate) async fn drain_writer<W>(
    write_half: W,
    rx: mpsc::Receiver<Frame>,
    deadlines: Arc<ConnectionDeadlines>,
) -> Result<(), ModuleError>
where
    W: AsyncWrite + Unpin,
{
    drain_writer_until(write_half, rx, deadlines, std::future::pending()).await
}

/// [`drain_writer`] for a connection whose shutdown owns its egress. Once
/// `closing` resolves the queue stops admitting frames, even while a detached
/// worker still holds a sender, and what is already queued gets one final
/// write and flush bounded by [`EGRESS_SEND_MS`].
pub(crate) async fn drain_writer_until<W>(
    write_half: W,
    mut rx: mpsc::Receiver<Frame>,
    deadlines: Arc<ConnectionDeadlines>,
    closing: impl std::future::Future<Output = ()>,
) -> Result<(), ModuleError>
where
    W: AsyncWrite + Unpin,
{
    let mut writer = BufWriter::new(write_half);
    let mut closing = std::pin::pin!(closing);
    let mut final_flush = None;
    loop {
        let frame = tokio::select! {
            frame = rx.recv() => frame,
            () = &mut closing, if final_flush.is_none() => {
                rx.close();
                final_flush = Some(tokio::time::Instant::now() + Duration::from_millis(EGRESS_SEND_MS));
                continue;
            }
        };
        let Some(frame) = frame else {
            break;
        };
        bounded(
            final_flush,
            write_batch(&mut writer, frame, &mut rx, &deadlines),
        )
        .await?;
    }
    bounded(final_flush, async {
        writer
            .flush()
            .await
            .map_err(|e| ModuleError::Message(e.to_string()))
    })
    .await
}

async fn bounded(
    end: Option<tokio::time::Instant>,
    work: impl std::future::Future<Output = Result<(), ModuleError>>,
) -> Result<(), ModuleError> {
    let Some(end) = end else {
        return work.await;
    };
    tokio::time::timeout_at(end, work)
        .await
        .map_err(|_| ModuleError::Message("final egress flush exceeded its deadline".into()))?
}

async fn write_batch<W>(
    writer: &mut BufWriter<W>,
    frame: Frame,
    rx: &mut mpsc::Receiver<Frame>,
    deadlines: &ConnectionDeadlines,
) -> Result<(), ModuleError>
where
    W: AsyncWrite + Unpin,
{
    let mut delivered = Vec::new();
    let mut displays = Vec::new();
    if matches!(frame.header.ty, FrameType::Response | FrameType::Error) {
        delivered.push(request_id(&frame));
        if let Some(display) = deadlines.display.get() {
            displays.extend(display.prepare(&frame));
        }
    }
    write_frame(writer, &frame)
        .await
        .map_err(|e| ModuleError::Message(e.to_string()))?;
    // Flush after at most one buffer's worth of frames, even if producers
    // continuously replenish the queue. A terminal reply that holds a slot
    // waits behind at most this batch plus one channel buffer.
    for _ in 1..EGRESS_BUFFER {
        let Ok(frame) = rx.try_recv() else {
            break;
        };
        if matches!(frame.header.ty, FrameType::Response | FrameType::Error) {
            delivered.push(request_id(&frame));
            if let Some(display) = deadlines.display.get() {
                displays.extend(display.prepare(&frame));
            }
        }
        write_frame(writer, &frame)
            .await
            .map_err(|e| ModuleError::Message(e.to_string()))?;
    }
    writer
        .flush()
        .await
        .map_err(|e| ModuleError::Message(e.to_string()))?;
    deadlines.delivered(&delivered);
    if let Some(records) = deadlines.display.get() {
        for display in displays {
            records.delivered(display);
        }
    }
    Ok(())
}

pub(crate) fn terminal_frame(frame: &Frame, request: RequestId) -> bool {
    matches!(frame.header.ty, FrameType::Response | FrameType::Error)
        && request_id(frame) == request
}

/// Serve one daemon connection: `run_loop` gets the egress sender, and the
/// connection ends when it returns and the writer has finished.
pub(crate) async fn drive_connection<W, F, Fut>(
    write_half: W,
    deadlines: Arc<ConnectionDeadlines>,
    run_loop: F,
) -> Result<(), ModuleError>
where
    W: AsyncWrite + Unpin + Send + 'static,
    F: FnOnce(mpsc::Sender<Frame>) -> Fut,
    Fut: std::future::Future<Output = Result<(), ModuleError>>,
{
    let (tx, rx) = mpsc::channel::<Frame>(EGRESS_BUFFER);
    // Shutdown owns egress: once the loop has ended and no terminal reply is
    // owed, close it even if a detached route worker still holds a sender.
    let (close, closed) = tokio::sync::oneshot::channel::<()>();
    let owed = Arc::clone(&deadlines);
    let closing = async move {
        let _ = closed.await;
        owed.settled().await
    };
    let mut writer = tokio::spawn(drain_writer_until(
        write_half,
        rx,
        Arc::clone(&deadlines),
        closing,
    ));
    let mut loop_task = Box::pin(run_loop(tx.clone()));

    let loop_result = tokio::select! {
        // Preserve the existing diagnostic precedence when both sides become
        // ready together: a concrete loop error is more specific than the
        // writer shutdown it can induce.
        biased;
        loop_result = &mut loop_task => loop_result,
        writer_result = &mut writer => {
            return crate::report_writer_first(crate::normalize_writer_task_result(writer_result));
        }
        _ = deadlines.expired() => {
            writer.abort();
            let _ = writer.await;
            return Err(ModuleError::Message("terminal delivery deadline exceeded".into()));
        }
    };

    drop(loop_task);
    drop(tx);
    let _ = close.send(());
    let writer_result = tokio::select! {
        result = &mut writer => crate::normalize_writer_task_result(result),
        _ = deadlines.expired() => {
            writer.abort();
            let _ = writer.await;
            Err(ModuleError::Message("terminal delivery deadline exceeded".into()))
        }
    };
    crate::reconcile_connection_results(loop_result, writer_result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use subc_protocol::{Flags, Priority};

    fn frame(ty: FrameType, corr: u64) -> Frame {
        Frame::build(
            ty,
            Flags::new(false, Priority::Interactive, false),
            9,
            1,
            corr,
            Vec::new(),
        )
        .unwrap()
    }

    /// A route worker detached past its terminal deadline keeps a sender to
    /// forward progress frames. When the connection loop ends, shutdown must
    /// still close egress and return, flushing what was already queued,
    /// instead of waiting for that worker to let go.
    #[tokio::test]
    async fn shutdown_closes_egress_without_waiting_for_a_detached_sender() {
        let (mut peer, socket) = tokio::io::duplex(1 << 16);
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let parked = Arc::clone(&gate);
        let deadlines = Arc::new(ConnectionDeadlines::default());
        let connection = drive_connection(socket, deadlines, |tx| async move {
            let detached = tx.clone();
            tokio::spawn(async move {
                let _sender = detached;
                let _ = parked.acquire().await;
            });
            tx.send(frame(FrameType::Push, 1)).await.unwrap();
            Ok(())
        });
        tokio::time::timeout(Duration::from_secs(5), connection)
            .await
            .expect("shutdown waited for a detached worker's sender")
            .unwrap();
        let flushed = subc_transport::read_frame(&mut peer)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(flushed.header.corr, 1);
        gate.add_permits(1);
    }

    /// Closing waits for terminal replies still owed on the connection, so a
    /// worker finishing just after the loop ends still delivers its reply.
    #[tokio::test]
    async fn shutdown_still_delivers_an_owed_terminal_reply() {
        let (mut peer, socket) = tokio::io::duplex(1 << 16);
        let deadlines = Arc::new(ConnectionDeadlines::default());
        deadlines.arm(
            (9, 1, 2),
            tokio::time::Instant::now() + crate::test_support::HANG_GUARD,
        );
        let connection = drive_connection(socket, deadlines, |tx| async move {
            let worker = tx.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                worker.send(frame(FrameType::Response, 2)).await.unwrap();
            });
            Ok(())
        });
        tokio::time::timeout(crate::test_support::HANG_GUARD, connection)
            .await
            .expect("the owed reply was delivered")
            .unwrap();
        let reply = subc_transport::read_frame(&mut peer)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply.header.corr, 2);
    }
}
