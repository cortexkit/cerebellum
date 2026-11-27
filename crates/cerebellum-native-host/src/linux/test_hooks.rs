//! Native-host controls for bridge integration fixtures, compiled only with
//! `bridge-test-identities`. `CK_BRIDGE_TEST_SOCKET` overrides the default
//! endpoint with an absolute path; ownership and mode checks still apply.
//! `CK_BRIDGE_TEST_CHECKPOINT` names a file overwritten with `step-1` or
//! `step-2` and a newline as each authentication worker begins its check.
//! `CK_BRIDGE_TEST_PAUSE` stalls the named step for ten seconds after that
//! checkpoint, longer than the host's authentication deadline.

use std::io;
use std::path::PathBuf;

pub(super) fn socket_override() -> io::Result<Option<PathBuf>> {
    let Some(path) = std::env::var_os("CK_BRIDGE_TEST_SOCKET").map(PathBuf::from) else {
        return Ok(None);
    };
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "test socket path must be absolute",
        ));
    }
    Ok(Some(path))
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
