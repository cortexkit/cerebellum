//! Host-side fixture controls. The pipe override changes only the local name;
//! the host still observes and authenticates the server before any hello.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::OsStrExt;

pub(super) fn pipe_override() -> io::Result<Option<OsString>> {
    std::env::var_os("CK_BRIDGE_TEST_PIPE")
        .map(local_pipe)
        .transpose()
}

fn local_pipe(name: OsString) -> io::Result<OsString> {
    let mut units = name.encode_wide().peekable();
    if OsStr::new(r"\\.\pipe\")
        .encode_wide()
        .all(|expected| units.next() == Some(expected))
        && units.peek().is_some()
        && units.all(|unit| !matches!(unit, 0 | 47 | 92))
    {
        Ok(name)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "test pipe must be a full local pipe name",
        ))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_a_full_local_pipe_name_with_one_leaf() {
        assert!(local_pipe(r"\\.\pipe\ck-test".into()).is_ok());
        for name in [
            r"\\127.0.0.1\pipe\ck-test",
            r"ck-test",
            r"\\.\pipe\",
            r"\\.\pipe\\nested",
            r"\\.\pipe\a/b",
            r"\\.\pipe\a\b",
            "\\\\.\\pipe\\a\0b",
        ] {
            assert!(local_pipe(name.into()).is_err(), "accepted {name:?}");
        }
    }
}
