use super::*;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let root = PathBuf::from(format!("/tmp/cknh-{label}-{}", std::process::id()));
        cerebellum_core::private_fs::create_dir(&root).unwrap();
        Self(root)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn endpoint_requires_the_expected_owner_and_exact_modes() {
    let scratch = Scratch::new("meta");
    let root = &scratch.0;
    let endpoint = root.join("socket");
    let _listener = UnixListener::bind(&endpoint).unwrap();
    fs::set_permissions(&endpoint, fs::Permissions::from_mode(0o600)).unwrap();
    let owner = fs::symlink_metadata(root).unwrap().uid();
    assert!(check_endpoint(&endpoint, owner).is_ok());
    assert_eq!(
        check_endpoint(&endpoint, owner ^ 1).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    let socket = fs::symlink_metadata(&endpoint).unwrap();
    assert!(owned_with_mode(&socket, owner, 0o600));
    assert!(!owned_with_mode(&socket, owner ^ 1, 0o600));

    for (path, mode) in [(root, 0o755), (&endpoint, 0o660)] {
        let permissions = fs::symlink_metadata(path).unwrap().permissions();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            check_endpoint(&endpoint, owner).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::set_permissions(path, permissions).unwrap();
    }
}

#[test]
fn full_linux_socket_backlog_refuses_without_waiting() {
    let scratch = Scratch::new("busy");
    let endpoint = scratch.0.join("socket");
    let listener = UnixListener::bind(&endpoint).unwrap();
    // SAFETY: listener is a live AF_UNIX listening descriptor. Linux permits
    // one queued connection for a zero backlog, so the second will not fit.
    assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 0) }, 0);
    let _queued = UnixStream::connect(&endpoint).unwrap();

    let pending = connect::PendingConnection::new(&endpoint).unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(pending.open());
    });
    let error = rx
        .recv_timeout(Duration::from_millis(500))
        .expect("connect waited for space in the server's backlog")
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert!(error.to_string().contains("cerebellum socket is busy"));

    let _accepted = listener.accept().unwrap();
    let connected = connect::PendingConnection::new(&endpoint)
        .unwrap()
        .open()
        .unwrap();
    // SAFETY: connected is live and F_GETFL reads its flags without an argument.
    let flags = unsafe { libc::fcntl(connected.as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0);
    assert_eq!(flags & libc::O_NONBLOCK, 0, "handshake needs blocking I/O");
}
