use super::admission::{admit, Admission, PeerIdentity};
use super::{Reason, UserBrowserBridge};
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};

#[cfg(test)]
use super::admission::{check_legacy_parent, CheckParent, PeerEvidence, VerifyPeer};
#[cfg(test)]
use super::BridgeListener;
#[cfg(test)]
use std::path::Path;

pub(super) struct SocketListener {
    bridge: UserBrowserBridge,
    task: tokio::task::JoinHandle<()>,
    path: PathBuf,
    inode: u64,
    device: u64,
}

impl SocketListener {
    pub(super) fn bind(
        bridge: UserBrowserBridge,
        path: PathBuf,
        admission: Admission,
    ) -> io::Result<Self> {
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
            accept_peers(instance, admission, || async {
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

async fn accept_peers<A, F>(instance: UserBrowserBridge, admission: Admission, mut accept: A)
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
                let admission = admission.clone();
                peers.spawn(async move {
                    let _slot = slot;
                    let identity = peer_identity(&stream);
                    admit(bridge, stream, identity, admission).await;
                });
            }
            _ = peers.join_next(), if !peers.is_empty() => {},
        }
    }
}

impl Drop for SocketListener {
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

fn peer_identity(stream: &UnixStream) -> Result<PeerIdentity, Reason> {
    if stream
        .peer_cred()
        .map_or(true, |credentials| credentials.uid() != current_uid())
    {
        return Err(Reason::WrongUser);
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsFd;
        stream
            .as_fd()
            .try_clone_to_owned()
            .map(PeerIdentity::MacOs)
            .map_err(|_| Reason::UnsignedPeer)
    }
    #[cfg(not(target_os = "macos"))]
    Ok(PeerIdentity::Test)
}

#[cfg(test)]
pub(super) use super::session::{read_frame, write_frame};

#[cfg(test)]
impl BridgeListener {
    fn bind_at(
        bridge: UserBrowserBridge,
        path: PathBuf,
        verifier: VerifyPeer,
        check_parent: CheckParent,
    ) -> io::Result<Self> {
        let socket =
            SocketListener::bind(bridge, path, Admission::injected(verifier, check_parent))?;
        Ok(Self { _socket: socket })
    }
}

#[cfg(test)]
pub(super) fn test_listener(
    bridge: UserBrowserBridge,
    path: &Path,
    signed: bool,
) -> io::Result<BridgeListener> {
    let verifier: VerifyPeer = if signed {
        Arc::new(|_| Ok(PeerEvidence::Test { _retained: None }))
    } else {
        #[cfg(target_os = "macos")]
        {
            Arc::new(super::admission::verify_signed_host)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Arc::new(|_| Err(Reason::UnsignedPeer))
        }
    };
    BridgeListener::bind_at(
        bridge,
        path.to_path_buf(),
        verifier,
        Arc::new(check_legacy_parent),
    )
}

#[cfg(test)]
mod admission_tests;

#[cfg(test)]
mod accept_tests {
    use super::*;
    use cerebellum_bridge_protocol::Frame;

    #[tokio::test(start_paused = true)]
    async fn audit_accept_errors_back_off_and_still_serve_the_next_peer() {
        let (server, mut client) = UnixStream::pair().unwrap();
        let attempts = Arc::new(std::sync::Mutex::new(Vec::new()));
        let times = attempts.clone();
        let mut server = Some(server);
        let task = tokio::spawn(accept_peers(
            UserBrowserBridge::new(),
            Admission::injected(
                Arc::new(|_| Err(Reason::ProtocolError)),
                Arc::new(check_legacy_parent),
            ),
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
