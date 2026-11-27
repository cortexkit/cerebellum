use super::*;
use cerebellum_bridge_protocol::peer_trailer::TEST_PEER_PUBLIC_KEY_HEX;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::Path;

#[cfg(feature = "bridge-test-identities")]
mod process;

const OPEN_REVISION: &str = if cfg!(feature = "bridge-test-identities") {
    "ci-unreviewed"
} else {
    "reviewed"
};

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let mut nonce = [0; 8];
        getrandom::getrandom(&mut nonce).unwrap();
        let root = Path::new("/tmp").join(format!("ck-bridge-{:016x}", u64::from_ne_bytes(nonce)));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        Self(root)
    }

    fn socket(&self) -> PathBuf {
        self.0.join("bridge.sock")
    }

    fn bind(&self) -> SocketListener {
        bind_with(
            UserBrowserBridge::new(),
            Some(OPEN_REVISION),
            Some(TEST_PEER_PUBLIC_KEY_HEX),
            linux::probe_kernel,
            || Ok((self.socket(), SocketPermissions::Private)),
        )
        .unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn unbound_gate_refuses_before_kernel_probe_or_endpoint_resolution() {
    for (revision, key) in [
        (None, Some(TEST_PEER_PUBLIC_KEY_HEX)),
        (Some(""), Some(TEST_PEER_PUBLIC_KEY_HEX)),
        (Some(OPEN_REVISION), None),
        (Some(OPEN_REVISION), Some("invalid")),
    ] {
        let result = bind_with(
            UserBrowserBridge::new(),
            revision,
            key,
            || panic!("an unbound gate must not probe"),
            || panic!("an unbound gate must not resolve the endpoint"),
        );
        assert!(
            matches!(result, Err(error) if error.kind() == io::ErrorKind::Unsupported
            && error.to_string() == "native messaging is not enabled in this build")
        );
    }
    if classify_bridge_gate(REVISION, PUBLIC_KEY).is_none() {
        let result = super::super::BridgeListener::bind(UserBrowserBridge::new());
        assert!(
            matches!(result, Err(error) if error.kind() == io::ErrorKind::Unsupported
            && error.to_string() == "native messaging is not enabled in this build")
        );
    }
}

#[test]
fn unsupported_kernel_leaves_no_endpoint_and_preserves_the_floor_message() {
    let scratch = Scratch::new();
    let result = bind_with(
        UserBrowserBridge::new(),
        Some(OPEN_REVISION),
        Some(TEST_PEER_PUBLIC_KEY_HEX),
        || {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "needs Linux 6.5+",
            ))
        },
        || Ok((scratch.socket(), SocketPermissions::Private)),
    );
    assert!(
        matches!(result, Err(error) if error.kind() == io::ErrorKind::Unsupported
        && error.to_string() == "needs Linux 6.5+")
    );
    assert!(!scratch.socket().exists());
}

#[tokio::test]
async fn open_gate_binds_and_refuses_unsigned_peer_without_waiting_for_hello() {
    use crate::user_browser_bridge::socket::read_frame;
    use cerebellum_bridge_protocol::Frame;
    use std::time::Duration;
    use tokio::net::UnixStream;

    let scratch = Scratch::new();
    let listener = scratch.bind();
    assert_eq!(fs::metadata(&scratch.0).unwrap().mode() & 0o7777, 0o700);
    assert_eq!(
        fs::metadata(scratch.socket()).unwrap().mode() & 0o7777,
        0o600
    );
    let mut peer = UnixStream::connect(scratch.socket()).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), read_frame(&mut peer))
            .await
            .expect("unsigned peer must not wait for a hello")
            .unwrap(),
        Frame::HostRefused {
            reason: "unsigned_peer".into()
        },
    );
    drop(listener);
    assert!(!scratch.socket().exists());
}

#[cfg(feature = "bridge-test-identities")]
#[tokio::test]
async fn permissive_listener_requires_the_fixture_to_supply_a_0755_directory() {
    use std::os::unix::fs::PermissionsExt;

    let scratch = Scratch::new();
    let bind = || {
        bind_with(
            UserBrowserBridge::new(),
            Some(OPEN_REVISION),
            Some(TEST_PEER_PUBLIC_KEY_HEX),
            linux::probe_kernel,
            || Ok((scratch.socket(), SocketPermissions::Permissive)),
        )
    };
    assert!(matches!(bind(), Err(error) if error.kind() == io::ErrorKind::PermissionDenied));
    assert!(!scratch.socket().exists());
    assert_eq!(fs::metadata(&scratch.0).unwrap().mode() & 0o7777, 0o700);
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o755)).unwrap();
    let _listener = bind().unwrap();
    assert_eq!(
        fs::metadata(scratch.socket()).unwrap().mode() & 0o7777,
        0o666
    );
}
