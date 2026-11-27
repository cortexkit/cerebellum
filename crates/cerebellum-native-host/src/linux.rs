use crate::relay::{establish_session, relay};
use cerebellum_bridge_protocol::linux::{attest_parent, observe_peer, VerifyingKey};
use cerebellum_bridge_protocol::{classify_bridge_gate, linux_socket_path};
use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

mod connect;
#[cfg(feature = "bridge-test-identities")]
mod test_hooks;
#[cfg(test)]
mod tests;

const CHECK_TIMEOUT: Duration = Duration::from_secs(1);

pub(super) fn build_key() -> io::Result<VerifyingKey> {
    classify_bridge_gate(
        option_env!("CEREBELLUM_LINUX_USER_BROWSER_REVIEW_REVISION"),
        option_env!("CEREBELLUM_BRIDGE_PEER_PUBLIC_KEY"),
    )
    .ok_or_else(crate::unbound_gate)
}

pub(super) fn run(key: VerifyingKey) -> io::Result<()> {
    let origin = crate::extension_origin(std::env::args_os())?;
    let (parent, connection) = check_on_worker(move || {
        #[cfg(feature = "bridge-test-identities")]
        test_hooks::checkpoint("step-1")?;
        let parent = attest_parent(&key)?;
        let path = socket_path()?;
        // SAFETY: geteuid takes no inputs and does not access caller-owned memory.
        check_endpoint(&path, unsafe { libc::geteuid() })?;
        let connection = connect::PendingConnection::new(&path)?;
        parent.check_before_connect()?;
        Ok((parent, connection))
    })?;

    let (socket, epoch) = establish_session(
        origin,
        || Ok(parent.attestation().clone()),
        // Keep the final parent decision on the worker. Only this thread can
        // connect, so a check that completes after the deadline cannot do so.
        || connection.open(),
        |socket| {
            let socket = socket.try_clone()?;
            check_on_worker(move || {
                #[cfg(feature = "bridge-test-identities")]
                test_hooks::checkpoint("step-2")?;
                let peer = observe_peer(&socket).map_err(io::Error::other)?;
                drop(socket);
                peer.verify_cerebellum(&key)
            })
        },
    )?;
    drop(parent);
    relay(socket, epoch, io::stdin(), &mut io::stdout().lock()).into_result()
}

fn socket_path() -> io::Result<PathBuf> {
    #[cfg(feature = "bridge-test-identities")]
    if let Some(path) = test_hooks::socket_override()? {
        return Ok(path);
    }
    linux_socket_path()
}

fn check_endpoint(path: &Path, euid: u32) -> io::Result<()> {
    let directory = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket has no parent directory",
        )
    })?;
    let dir = fs::symlink_metadata(directory)?;
    if !dir.is_dir() || !owned_with_mode(&dir, euid, 0o700) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "bridge socket directory must be owned by the current user and have mode 0700",
        ));
    }
    let socket = fs::symlink_metadata(path)?;
    if !socket.file_type().is_socket() || !owned_with_mode(&socket, euid, 0o600) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "bridge socket must be owned by the current user and have mode 0600",
        ));
    }
    Ok(())
}

fn owned_with_mode(metadata: &fs::Metadata, euid: u32, mode: u32) -> bool {
    metadata.uid() == euid && metadata.mode() & 0o7777 == mode
}

fn check_on_worker<T: Send + 'static>(
    check: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    let deadline = Instant::now() + CHECK_TIMEOUT;
    let (tx, rx) = mpsc::channel();
    // The check owns its inputs; dropping the thread handle leaves it
    // detached so a stalled filesystem read cannot hold the process open.
    thread::Builder::new().spawn(move || {
        let _ = tx.send(check());
    })?;

    let result = rx.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    match result {
        Ok(result) if Instant::now() < deadline => result,
        Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "bridge authentication check timed out",
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(io::Error::other("bridge authentication worker stopped"))
        }
    }
}
