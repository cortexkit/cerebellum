use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;

pub(super) struct PendingConnection {
    address: libc::sockaddr_un,
    length: libc::socklen_t,
    socket: UnixStream,
}

impl PendingConnection {
    pub(super) fn new(path: &Path) -> io::Result<Self> {
        // SAFETY: sockaddr_un contains only integers and an array of integers.
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        let path = path.as_os_str().as_bytes();
        if path.is_empty() || path.contains(&0) || path.len() >= address.sun_path.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Unix socket path",
            ));
        }
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (slot, byte) in address.sun_path.iter_mut().zip(path) {
            *slot = *byte as libc::c_char;
        }
        let length =
            (std::mem::offset_of!(libc::sockaddr_un, sun_path) + path.len() + 1) as libc::socklen_t;
        // SAFETY: the constants request a new close-on-exec Unix stream socket.
        let fd = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: socket succeeded and returned a new, exclusively owned fd.
        let socket = unsafe { UnixStream::from_raw_fd(fd) };
        Ok(Self {
            address,
            length,
            socket,
        })
    }

    pub(super) fn open(self) -> io::Result<UnixStream> {
        // A same-user listener can fill its backlog. A blocking connect would
        // wait for that listener before any handshake deadline can take effect.
        // SAFETY: the socket is live and length covers the initialized Unix
        // address through the path's terminating NUL, within the struct.
        let result = unsafe {
            libc::connect(
                self.socket.as_raw_fd(),
                (&self.address as *const libc::sockaddr_un).cast(),
                self.length,
            )
        };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EAGAIN) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "cerebellum socket is busy or blocked by another process of this user",
                ));
            }
            return Err(error);
        }
        self.socket.set_nonblocking(false)?;
        Ok(self.socket)
    }
}
