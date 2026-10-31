//! Request delivery deadlines and bounded write-and-flush batches.

use std::sync::Arc;

use subc_protocol::{Frame, FrameType};
use tokio::io::{AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;

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
    pub(crate) display: Arc<crate::tool_display::Records>,
}

impl ConnectionDeadlines {
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

pub(crate) async fn drain_writer<W>(
    write_half: W,
    mut rx: mpsc::Receiver<Frame>,
    deadlines: Arc<ConnectionDeadlines>,
) -> Result<(), ModuleError>
where
    W: AsyncWrite + Unpin,
{
    let mut writer = BufWriter::new(write_half);
    while let Some(frame) = rx.recv().await {
        let mut delivered = Vec::new();
        let mut displays = Vec::new();
        if matches!(frame.header.ty, FrameType::Response | FrameType::Error) {
            delivered.push(request_id(&frame));
            displays.extend(deadlines.display.prepare(&frame));
        }
        write_frame(&mut writer, &frame)
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
                displays.extend(deadlines.display.prepare(&frame));
            }
            write_frame(&mut writer, &frame)
                .await
                .map_err(|e| ModuleError::Message(e.to_string()))?;
        }
        writer
            .flush()
            .await
            .map_err(|e| ModuleError::Message(e.to_string()))?;
        deadlines.delivered(&delivered);
        for display in displays {
            deadlines.display.delivered(display);
        }
    }
    writer
        .flush()
        .await
        .map_err(|e| ModuleError::Message(e.to_string()))?;
    Ok(())
}

pub(crate) fn terminal_frame(frame: &Frame, request: RequestId) -> bool {
    matches!(frame.header.ty, FrameType::Response | FrameType::Error)
        && request_id(frame) == request
}
