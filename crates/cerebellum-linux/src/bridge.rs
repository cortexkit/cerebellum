//! Raw Linux syscall, procfs and dpkg readings for the native-messaging handshake.

use std::io;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;

mod dpkg;
mod process;

pub use dpkg::{
    open_root_image, read_dpkg_file_list_contains, read_dpkg_records, read_dpkg_status, DpkgRecord,
};
pub use process::{
    open_executable, read_effective_uid, read_executable_metadata, read_executable_path,
    read_parent_pid, read_peer_credentials, PeerCredentials, PidFd, ProcessStat,
};

/// Try both pidfd primitives on this kernel without reading procfs.
pub fn observe_kernel_pidfds() -> io::Result<()> {
    bind_probe(PidFd::open_process(std::process::id()))?;
    let (socket, _peer) = UnixStream::pair()?;
    bind_probe(PidFd::open_peer(socket.as_fd()))?;
    Ok(())
}

fn bind_probe<T>(result: io::Result<T>) -> io::Result<T> {
    result.map_err(|error| match error.raw_os_error() {
        Some(libc::ENOSYS | libc::ENOPROTOOPT | libc::EINVAL) => {
            io::Error::new(io::ErrorKind::Unsupported, "needs Linux 6.5+")
        }
        _ => error,
    })
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_bind_probe_maps_unsupported_primitives_to_the_kernel_floor() {
        for errno in [libc::ENOSYS, libc::ENOPROTOOPT, libc::EINVAL] {
            let error = bind_probe::<()>(Err(io::Error::from_raw_os_error(errno))).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            assert_eq!(error.to_string(), "needs Linux 6.5+");
        }
        for errno in [libc::EPERM, libc::EACCES, libc::ESRCH, libc::ENOENT] {
            let denied = bind_probe::<()>(Err(io::Error::from_raw_os_error(errno))).unwrap_err();
            assert_eq!(denied.raw_os_error(), Some(errno));
            assert!(!denied.to_string().contains("needs Linux 6.5+"));
        }
    }
}
