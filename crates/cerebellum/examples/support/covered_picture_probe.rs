//! Approval and text-free output for the probe that photographs its own
//! TextEdit window after the foreground application covers it.

use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const ROOT: &str = "/tmp/cereb-desk";

unsafe extern "C" {
    fn geteuid() -> u32;
    fn dup2(old: i32, new: i32) -> i32;
}

fn private_directory(path: &Path, uid: u32) -> bool {
    std::fs::symlink_metadata(path)
        .is_ok_and(|m| m.is_dir() && m.mode() & 0o7777 == 0o700 && m.uid() == uid)
}

fn private_data_home(root: &Path, path: &Path, uid: u32) -> bool {
    let Ok(root) = root.canonicalize() else {
        return false;
    };
    path.is_absolute()
        && private_directory(path, uid)
        && path.parent().and_then(|p| p.canonicalize().ok()).as_ref() == Some(&root)
        && path.canonicalize().is_ok_and(|p| p.parent() == Some(&root))
}

/// Redirect output before any permission or desktop check. Never reuse an
/// existing file at the log path, even if it is a normal file.
pub(super) fn open_log(approved: bool) -> Option<PathBuf> {
    let root = Path::new(ROOT);
    // SAFETY: geteuid has no arguments or memory preconditions.
    let uid = unsafe { geteuid() };
    if !private_directory(root, uid) {
        return None;
    }
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("run-covered-picture.log"))
        .ok()?;
    // SAFETY: file owns a live descriptor; dup2 keeps its own references for
    // stdout and stderr. The probe does no further work if either fails.
    if unsafe { dup2(file.as_raw_fd(), 1) < 0 || dup2(file.as_raw_fd(), 2) < 0 } {
        return None;
    }
    let data_home = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from);
    if approved && std::env::var_os("CK_DESK_PROBE_APPROVED").as_deref() == Some("1".as_ref()) {
        if let Some(path) = data_home.filter(|path| private_data_home(root, path, uid)) {
            return Some(path);
        }
    }
    eprintln!("REFUSED: approval flag, CK_DESK_PROBE_APPROVED=1 and private scratch XDG_DATA_HOME required");
    None
}
