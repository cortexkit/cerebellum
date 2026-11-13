//! Darwin-only control plumbing. SCM_RIGHTS transfers copies before the quiet
//! interval; readiness and shutdown always use a different socket from the one
//! whose peer identity is being measured.

use std::ffi::{c_int, c_void};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

#[repr(C)]
struct Iovec {
    base: *mut c_void,
    len: usize,
}
#[repr(C)]
struct Message {
    name: *mut c_void,
    name_len: u32,
    iov: *mut Iovec,
    iov_len: c_int,
    control: *mut c_void,
    control_len: u32,
    flags: c_int,
}

extern "C" {
    fn sendmsg(fd: c_int, message: *const Message, flags: c_int) -> isize;
    fn recvmsg(fd: c_int, message: *mut Message, flags: c_int) -> isize;
    fn getsockopt(
        fd: c_int,
        level: c_int,
        name: c_int,
        value: *mut c_void,
        size: *mut u32,
    ) -> c_int;
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
    fn getuid() -> u32;
    fn geteuid() -> u32;
    fn kill(pid: c_int, signal: c_int) -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
}

pub(super) fn uid() -> io::Result<u32> {
    // SAFETY: these identity queries take no pointers.
    let (real, effective) = unsafe { (getuid(), geteuid()) };
    if real != effective {
        return Err(io::Error::other("setuid probe refused"));
    }
    Ok(real)
}

pub(super) fn peer_token(socket: &UnixStream) -> io::Result<[u32; 8]> {
    let mut token = [0u32; 8];
    let mut size = 32;
    // SAFETY: Darwin sys/un.h defines LOCAL_PEERTOKEN=6 at SOL_LOCAL=0,
    // returning an audit_token_t (eight u32s), not a pid or a payload claim.
    let status = unsafe {
        getsockopt(
            socket.as_raw_fd(),
            0,
            6,
            token.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    if size != 32 {
        return Err(io::Error::other("wrong LOCAL_PEERTOKEN size"));
    }
    Ok(token)
}

pub(super) fn inheritable(fd: c_int, inherit: bool) -> io::Result<()> {
    // SAFETY: F_GETFD=1 and F_SETFD=2 operate on the supplied live descriptor.
    let flags = unsafe { fcntl(fd, 1) };
    if flags < 0 || unsafe { fcntl(fd, 2, if inherit { flags & !1 } else { flags | 1 }) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn send_fds(control: &UnixStream, fds: &[c_int]) -> io::Result<()> {
    if !(1..=3).contains(&fds.len()) {
        return Err(io::Error::other("bad fd count"));
    }
    // Darwin CMSG alignment is four bytes. Header: length, SOL_SOCKET, SCM_RIGHTS.
    let mut ancillary = [0u32; 6];
    ancillary[0] = 12 + 4 * fds.len() as u32;
    ancillary[1] = 0xffff;
    ancillary[2] = 1;
    for (out, fd) in ancillary[3..].iter_mut().zip(fds) {
        *out = *fd as u32;
    }
    let mut byte = 0xf1u8;
    let mut iov = Iovec {
        base: (&mut byte as *mut u8).cast(),
        len: 1,
    };
    let message = Message {
        name: std::ptr::null_mut(),
        name_len: 0,
        iov: &mut iov,
        iov_len: 1,
        control: ancillary.as_mut_ptr().cast(),
        control_len: ancillary[0],
        flags: 0,
    };
    // SAFETY: the message points into live, correctly aligned buffers above.
    if unsafe { sendmsg(control.as_raw_fd(), &message, 0) } != 1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn recv_fds(control: &UnixStream, count: usize) -> io::Result<Vec<OwnedFd>> {
    let mut ancillary = [0u32; 6];
    let mut byte = 0u8;
    let mut iov = Iovec {
        base: (&mut byte as *mut u8).cast(),
        len: 1,
    };
    let mut message = Message {
        name: std::ptr::null_mut(),
        name_len: 0,
        iov: &mut iov,
        iov_len: 1,
        control: ancillary.as_mut_ptr().cast(),
        control_len: 24,
        flags: 0,
    };
    // SAFETY: the kernel receives live, writable buffers with Darwin layouts.
    let received = unsafe { recvmsg(control.as_raw_fd(), &mut message, 0) };
    if received != 1 {
        return Err(io::Error::other("descriptor handoff failed"));
    }
    let length = ancillary[0] as usize;
    let valid_header = (12..=24).contains(&length)
        && length.is_multiple_of(4)
        && ancillary[1] == 0xffff
        && ancillary[2] == 1;
    // Adopt every received descriptor even on a malformed marker, so error
    // paths close the kernel-installed copies rather than leaking authority.
    let mut descriptors = Vec::new();
    if valid_header {
        for &fd in &ancillary[3..length / 4] {
            // SAFETY: a validated SCM_RIGHTS header contains new owned fds.
            let owned = unsafe { OwnedFd::from_raw_fd(fd as c_int) };
            descriptors.push(owned);
        }
    }
    if !valid_header || message.flags & 0x20 != 0 || byte != 0xf1 || descriptors.len() != count {
        return Err(io::Error::other("invalid descriptor handoff"));
    }
    for fd in &descriptors {
        inheritable(fd.as_raw_fd(), false)?;
    }
    Ok(descriptors)
}

pub(super) fn reap(pid: u32) -> io::Result<()> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(io::Error::other("invalid child pid"));
    }
    loop {
        let mut status = 0;
        // SAFETY: wait only for the explicit owned child, with a writable status.
        if unsafe { waitpid(pid as c_int, &mut status, 0) } >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

pub(super) fn terminate_and_reap(pid: u32) -> io::Result<()> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(io::Error::other("invalid child pid"));
    }
    let mut status = 0;
    // SAFETY: WNOHANG=1 first proves this is our own unreaped child. Refuse a
    // non-child rather than accepting a pid supplied on a role's command line.
    let state = unsafe { waitpid(pid as c_int, &mut status, 1) };
    if state < 0 {
        return Err(io::Error::last_os_error());
    }
    if state == pid as c_int {
        return Ok(());
    }
    // SAFETY: the still-unreaped direct child cannot have its pid reused.
    if unsafe { kill(pid as c_int, 9) } != 0 {
        return Err(io::Error::last_os_error());
    }
    reap(pid)
}
