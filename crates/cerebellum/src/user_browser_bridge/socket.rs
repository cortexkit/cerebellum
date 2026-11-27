use super::*;
use cerebellum_bridge_protocol::{
    checked_length, decode_body, encode, Frame, ParentAttestation, EXTENSION_ORIGIN,
    PROTOCOL_VERSION,
};
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

type VerifyPeer = Arc<dyn Fn(&std::os::unix::net::UnixStream) -> Result<(), Reason> + Send + Sync>;

/// Owns the private socket and its accept loop. Dropping it stops the listener
/// and connection; it never sends signals to Chrome or closes any browser tab.
pub struct BridgeListener {
    bridge: UserBrowserBridge,
    task: tokio::task::JoinHandle<()>,
    path: PathBuf,
    inode: u64,
    device: u64,
}

impl BridgeListener {
    #[cfg(target_os = "macos")]
    pub fn bind(bridge: UserBrowserBridge) -> io::Result<Self> {
        let path = cortexkit_paths::cortexkit_run_dir()
            .map_err(io::Error::other)?
            .join("cerebellum/user-browser.sock");
        Self::bind_at(bridge, path, Arc::new(verify_signed_host))
    }

    fn bind_at(bridge: UserBrowserBridge, path: PathBuf, verifier: VerifyPeer) -> io::Result<Self> {
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "socket has no parent"))?;
        cerebellum_core::private_fs::create_dir_all(parent)?;
        let directory = std::fs::symlink_metadata(parent)?;
        if !directory.is_dir()
            || directory.uid() != current_uid()
            || directory.mode() & 0o777 != 0o700
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "bridge directory must be owned by the current user with mode 0700",
            ));
        }
        if let Ok(metadata) = std::fs::symlink_metadata(&path) {
            if !metadata.file_type().is_socket() || metadata.uid() != current_uid() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "existing bridge path is not an owned socket",
                ));
            }
            match std::os::unix::net::UnixStream::connect(&path) {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "a bridge server is already listening",
                    ))
                }
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                    std::fs::remove_file(&path)?
                }
                Err(error) => return Err(error),
            }
        }
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let metadata = std::fs::symlink_metadata(&path)?;
        let instance = bridge.clone();
        let task = tokio::spawn(async move {
            accept_peers(instance, verifier, || async {
                listener.accept().await.map(|(stream, _)| stream)
            })
            .await;
        });
        Ok(Self {
            bridge,
            task,
            path,
            inode: metadata.ino(),
            device: metadata.dev(),
        })
    }
}

async fn accept_peers<A, F>(instance: UserBrowserBridge, verifier: VerifyPeer, mut accept: A)
where
    A: FnMut() -> F,
    F: std::future::Future<Output = io::Result<UnixStream>>,
{
    let slots = Arc::new(tokio::sync::Semaphore::new(8));
    let mut peers = tokio::task::JoinSet::new();
    let mut retry = Duration::from_millis(10);
    loop {
        tokio::select! {
            accepted = accept() => {
                let stream = match accepted {
                    Ok(stream) => {
                        retry = Duration::from_millis(10);
                        stream
                    }
                    Err(_) => {
                        // Descriptor pressure and aborted connections can clear
                        // without a rebind. Back off up to one second rather
                        // than spinning on a persistent error.
                        tokio::time::sleep(retry).await;
                        retry = (retry * 2).min(Duration::from_secs(1));
                        continue;
                    }
                };
                let Ok(slot) = slots.clone().try_acquire_owned() else { continue; };
                let bridge = instance.clone();
                let verifier = verifier.clone();
                peers.spawn(async move {
                    let _slot = slot;
                    serve_peer(bridge, stream, verifier).await;
                });
            }
            _ = peers.join_next(), if !peers.is_empty() => {},
        }
    }
}

impl Drop for BridgeListener {
    fn drop(&mut self) {
        self.bridge.shutdown();
        self.task.abort();
        // Do not remove a path another process substituted after this bind.
        if let Ok(metadata) = std::fs::symlink_metadata(&self.path) {
            if metadata.ino() == self.inode && metadata.dev() == self.device {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
}

fn current_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[cfg(target_os = "macos")]
fn verify_signed_host(stream: &std::os::unix::net::UnixStream) -> Result<(), Reason> {
    cerebellum_macos::peer_satisfies_requirement(
        stream,
        cerebellum_bridge_protocol::HOST_REQUIREMENT,
        HOST_HELLO_DEADLINE,
    )
    .map(|_| ())
    .map_err(|_| Reason::UnsignedPeer)
}

fn valid_parent(parent: &ParentAttestation) -> bool {
    if parent.pid == 0 || parent.start_time_micros == 0 {
        return false;
    }
    match (&parent.team_id, &parent.probe_cdhash) {
        (Some(team), None) => team == "EQHXZ8M8AV",
        #[cfg(feature = "chrome-for-testing-parent-probe")]
        (None, Some(hash)) => hash == "8f2a5ce4af6d1cd71fe66113dd809e4d106c3106",
        _ => false,
    }
}

async fn serve_peer(bridge: UserBrowserBridge, mut stream: UnixStream, verifier: VerifyPeer) {
    if stream
        .peer_cred()
        .map_or(true, |credentials| credentials.uid() != current_uid())
    {
        refuse(&mut stream, Reason::WrongUser).await;
        return;
    }
    // Running-code checks can block. Keep the runtime available for Cancel and
    // phase deadlines while the bounded signing operation runs elsewhere.
    let Ok(raw) = stream.into_std() else {
        return;
    };
    let checked = tokio::task::spawn_blocking(move || {
        let verdict = verifier(&raw);
        (raw, verdict)
    })
    .await;
    let Ok((raw, verdict)) = checked else {
        return;
    };
    let Ok(mut stream) = UnixStream::from_std(raw) else {
        return;
    };
    if let Err(reason) = verdict {
        refuse(&mut stream, reason).await;
        return;
    }
    let hello = tokio::time::timeout(HOST_HELLO_DEADLINE, read_frame(&mut stream)).await;
    let reason = match hello {
        Ok(Ok(Frame::HostHello {
            protocol,
            extension_origin,
            parent,
        })) => {
            if protocol != PROTOCOL_VERSION {
                Some(Reason::ProtocolMismatch)
            } else if extension_origin != EXTENSION_ORIGIN {
                Some(Reason::ExtensionOriginMismatch)
            } else if !parent.as_legacy().is_some_and(valid_parent) {
                Some(Reason::ParentAttestationInvalid)
            } else {
                None
            }
        }
        _ => Some(Reason::ProtocolError),
    };
    if let Some(reason) = reason {
        refuse(&mut stream, reason).await;
        return;
    }
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
    let (mut reader, mut writer) = stream.into_split();
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

async fn refuse(stream: &mut UnixStream, reason: Reason) {
    let reason = serde_json::to_value(reason)
        .expect("reason serializes")
        .as_str()
        .expect("reason is a string")
        .to_owned();
    let _ = write_frame(stream, &Frame::HostRefused { reason }).await;
}

pub(super) async fn read_frame(
    reader: &mut (impl tokio::io::AsyncRead + Unpin),
) -> io::Result<Frame> {
    let mut prefix = [0; 4];
    reader.read_exact(&mut prefix).await?;
    let mut body = vec![0; checked_length(prefix)?];
    reader.read_exact(&mut body).await?;
    decode_body(&body)
}

pub(super) async fn write_frame(
    writer: &mut (impl tokio::io::AsyncWrite + Unpin),
    frame: &Frame,
) -> io::Result<()> {
    let bytes = encode(frame)?;
    tokio::time::timeout(WRITE_DEADLINE, writer.write_all(&bytes))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "bridge write deadline"))?
}

#[cfg(test)]
pub(super) fn test_listener(
    bridge: UserBrowserBridge,
    path: &Path,
    signed: bool,
) -> io::Result<BridgeListener> {
    let verifier: VerifyPeer = if signed {
        Arc::new(|_| Ok(()))
    } else {
        #[cfg(target_os = "macos")]
        {
            Arc::new(verify_signed_host)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Arc::new(|_| Err(Reason::UnsignedPeer))
        }
    };
    BridgeListener::bind_at(bridge, path.to_path_buf(), verifier)
}

#[cfg(test)]
mod accept_tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn audit_accept_errors_back_off_and_still_serve_the_next_peer() {
        let (server, mut client) = UnixStream::pair().unwrap();
        let attempts = Arc::new(std::sync::Mutex::new(Vec::new()));
        let times = attempts.clone();
        let mut server = Some(server);
        let task = tokio::spawn(accept_peers(
            UserBrowserBridge::new(),
            Arc::new(|_| Err(Reason::ProtocolError)),
            move || {
                let index = {
                    let mut times = times.lock().unwrap();
                    let index = times.len();
                    times.push(tokio::time::Instant::now());
                    index
                };
                let stream = if index == 8 { server.take() } else { None };
                async move {
                    if index < 8 {
                        Err(io::Error::from(io::ErrorKind::ConnectionAborted))
                    } else if let Some(stream) = stream {
                        Ok(stream)
                    } else {
                        std::future::pending().await
                    }
                }
            },
        ));
        let reply = tokio::time::timeout(Duration::from_secs(10), read_frame(&mut client))
            .await
            .expect("accept retries must reach a reconnected peer")
            .expect("the listener must not exit on an accept error");
        assert!(matches!(reply, Frame::HostRefused { .. }));
        let times = attempts.lock().unwrap();
        assert!(times.len() >= 9);
        for (index, pair) in times[..9].windows(2).enumerate() {
            assert_eq!(
                pair[1] - pair[0],
                Duration::from_millis((10u64 << index).min(1000))
            );
        }
        task.abort();
    }
}
