//! The test build may bind a local `CK_BRIDGE_TEST_PIPE` instead of the user's
//! pipe. `CK_BRIDGE_TEST_SECOND_USER_SID` adds one DACL entry to the override
//! only; the listener still checks the connected process's SID.
//!
//! `CK_BRIDGE_TEST_CHECKPOINT` records `step-3` once the SID check has passed
//! or `step-3-parent` before the listener re-walks the host's launch chain.
//! `CK_BRIDGE_TEST_PAUSE` stalls the named worker just after its checkpoint.

use super::PipeEndpoint;
use std::io;
use std::time::Duration;

pub(super) fn endpoint_override(user: &str) -> io::Result<Option<PipeEndpoint>> {
    let name = test_var("CK_BRIDGE_TEST_PIPE")?;
    let second_user = test_var("CK_BRIDGE_TEST_SECOND_USER_SID")?;
    match (name, second_user) {
        (None, None) => Ok(None),
        (Some(name), second_user)
            if name
                .strip_prefix(r"\\.\pipe\")
                .is_some_and(|leaf| !leaf.is_empty() && !leaf.contains(['\\', '/', '\0'])) =>
        {
            Ok(Some(PipeEndpoint {
                name,
                user: user.into(),
                second_user,
            }))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "test pipe override must name a local named pipe",
        )),
    }
}

fn test_var(name: &str) -> io::Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(io::Error::new(io::ErrorKind::InvalidInput, error)),
    }
}

pub(super) fn checkpoint(step: &str) -> io::Result<()> {
    if let Some(path) = std::env::var_os("CK_BRIDGE_TEST_CHECKPOINT") {
        std::fs::write(path, format!("{step}\n"))?;
    }
    if std::env::var_os("CK_BRIDGE_TEST_PAUSE").is_some_and(|pause| pause == step) {
        std::thread::sleep(Duration::from_secs(10));
    }
    Ok(())
}
