use super::*;
use cerebellum_bridge_protocol::{checked_length, decode_body, encode, Frame, PROTOCOL_VERSION};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(super) async fn serve_session(
    bridge: UserBrowserBridge,
    mut stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
) {
    let (epoch, mut outgoing, mut closed) = match bridge.connect() {
        Ok(connection) => connection,
        Err(reason) => {
            refuse(&mut stream, reason).await;
            return;
        }
    };
    let mut connection = DisconnectOnDrop {
        bridge: bridge.clone(),
        epoch,
        reason: DisconnectReason::Shutdown,
    };
    if let Err(error) = write_frame(
        &mut stream,
        &Frame::HostAccepted {
            protocol: PROTOCOL_VERSION,
            epoch,
        },
    )
    .await
    {
        connection.reason = write_end_reason(&error);
        return;
    }
    let (mut reader, mut writer) = tokio::io::split(stream);
    let receiving = bridge.clone();
    let read_task = tokio::spawn(async move {
        let reason = loop {
            let message = match read_frame(&mut reader).await {
                Ok(Frame::Relay { message }) => message,
                Ok(_) => break DisconnectReason::ProtocolError,
                Err(error) => break read_end_reason(&error),
            };
            if serde_json::to_vec(&message).map_or(true, |bytes| bytes.len() > MAX_MESSAGE_BYTES) {
                break DisconnectReason::ProtocolError;
            }
            let Ok(message) = serde_json::from_value::<Message>(message) else {
                break DisconnectReason::ProtocolError;
            };
            receiving.receive(message);
        };
        receiving.disconnect(epoch, reason);
    });
    let _reader = AbortOnDrop(read_task);
    let writing = async {
        while let Some(message) = outgoing.recv().await {
            if !bridge.should_send(&message) {
                continue;
            }
            let Ok(value) = serde_json::to_value(message) else {
                return DisconnectReason::WriteError;
            };
            if let Err(error) = write_frame(&mut writer, &Frame::Relay { message: value }).await {
                return write_end_reason(&error);
            }
        }
        // `outgoing` ends only after `disconnect` has removed this connection
        // from the bridge, and `disconnect` records the end with its own reason
        // first, so this value is never the one recorded.
        DisconnectReason::PeerClosed
    };
    tokio::select! {
        _ = wait_closed(&mut closed) => {},
        reason = writing => connection.reason = reason,
    }
}

/// What a failed socket read says about how the connection ended.
fn read_end_reason(error: &io::Error) -> DisconnectReason {
    match error.kind() {
        io::ErrorKind::UnexpectedEof => DisconnectReason::PeerClosed,
        // The protocol crate reports oversized and undecodable frames as
        // invalid data.
        io::ErrorKind::InvalidData => DisconnectReason::ProtocolError,
        _ => DisconnectReason::ReadError,
    }
}

/// What a failed frame write says about how the connection ended.
fn write_end_reason(error: &io::Error) -> DisconnectReason {
    match error.kind() {
        // `write_frame` reports its own deadline as timed out.
        io::ErrorKind::TimedOut => DisconnectReason::WriteStalled,
        _ => DisconnectReason::WriteError,
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}
/// Ends the connection when the peer task stops for any reason. `reason` is
/// what this task saw; it stays `Shutdown` only when the task stopped without
/// seeing an end of its own: the close signal fired (the bridge already holds
/// the earlier reason, which takes precedence) or the listener aborted the task
/// while shutting down.
struct DisconnectOnDrop {
    bridge: UserBrowserBridge,
    epoch: u64,
    reason: DisconnectReason,
}
impl Drop for DisconnectOnDrop {
    fn drop(&mut self) {
        self.bridge.disconnect(self.epoch, self.reason);
    }
}

pub(super) async fn refuse(stream: &mut (impl AsyncWrite + Unpin), reason: Reason) {
    let reason = serde_json::to_value(reason)
        .expect("reason serializes")
        .as_str()
        .expect("reason is a string")
        .to_owned();
    let _ = write_frame(stream, &Frame::HostRefused { reason }).await;
}

pub(super) async fn read_frame(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<Frame> {
    let mut prefix = [0; 4];
    reader.read_exact(&mut prefix).await?;
    let mut body = vec![0; checked_length(prefix)?];
    reader.read_exact(&mut body).await?;
    decode_body(&body)
}

pub(super) async fn write_frame(
    writer: &mut (impl AsyncWrite + Unpin),
    frame: &Frame,
) -> io::Result<()> {
    let bytes = encode(frame)?;
    tokio::time::timeout(WRITE_DEADLINE, writer.write_all(&bytes))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "bridge write deadline"))?
}
