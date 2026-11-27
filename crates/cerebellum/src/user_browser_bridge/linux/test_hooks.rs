//! Listener controls for integration fixtures. `CK_BRIDGE_TEST_SOCKET` selects
//! an absolute path. `CK_BRIDGE_TEST_PERMISSIVE=1` also requires that override
//! and a pre-created, owned 0755 directory; only the listener socket is 0666.
//! The native host's ownership and mode checks are unaffected.
//!
//! `CK_BRIDGE_TEST_CHECKPOINT` is overwritten with `step-3` when peer image
//! verification starts (after the UID check), or `step-3-parent` when the
//! parent re-check starts, followed by a newline. `CK_BRIDGE_TEST_PAUSE` stalls
//! the named worker for ten seconds after its checkpoint.

use super::SocketPermissions;
use std::io;
use std::path::PathBuf;

pub(super) fn endpoint_override() -> io::Result<Option<(PathBuf, SocketPermissions)>> {
    let permissive =
        std::env::var_os("CK_BRIDGE_TEST_PERMISSIVE").is_some_and(|value| value == "1");
    let path = std::env::var_os("CK_BRIDGE_TEST_SOCKET").map(PathBuf::from);
    match path {
        Some(path) if path.is_absolute() => Ok(Some((
            path,
            if permissive {
                SocketPermissions::Permissive
            } else {
                SocketPermissions::Private
            },
        ))),
        None if !permissive => Ok(None),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "test socket path must be absolute",
        )),
    }
}

pub(super) fn checkpoint(step: &str) -> io::Result<()> {
    if let Some(path) = std::env::var_os("CK_BRIDGE_TEST_CHECKPOINT") {
        std::fs::write(path, format!("{step}\n"))?;
    }
    if std::env::var_os("CK_BRIDGE_TEST_PAUSE").is_some_and(|pause| pause == step) {
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
    Ok(())
}
