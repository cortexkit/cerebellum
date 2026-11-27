use std::fs;
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use super::invalid;

#[derive(Debug)]
pub(super) struct PidFd(OwnedFd);

impl PidFd {
    pub(super) fn open(pid: u32) -> io::Result<Self> {
        let pid = libc::pid_t::try_from(pid)
            .ok()
            .filter(|&pid| pid > 0)
            .ok_or_else(|| invalid("invalid process ID"))?;
        // SAFETY: pidfd_open takes a numeric pid and flags, not pointers.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
        if fd == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a successful pidfd_open returns a new, owned descriptor.
        Ok(Self(unsafe { OwnedFd::from_raw_fd(fd as RawFd) }))
    }

    pub(super) fn for_peer(socket: BorrowedFd<'_>) -> io::Result<Self> {
        let mut fd: libc::c_int = -1;
        let mut len = size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: socket is borrowed for the call; SO_PEERPIDFD writes one int.
        let result = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERPIDFD,
                (&mut fd as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        if result == -1 {
            return Err(io::Error::last_os_error());
        }
        if fd < 0 {
            return Err(invalid("missing socket peer pidfd"));
        }
        // SAFETY: a successful SO_PEERPIDFD call returns a new, owned fd.
        let pidfd = Self(unsafe { OwnedFd::from_raw_fd(fd) });
        if len as usize != size_of::<libc::c_int>() {
            return Err(invalid("invalid socket peer pidfd size"));
        }
        Ok(pidfd)
    }

    pub(super) fn require_pid(&self, pid: u32) -> io::Result<()> {
        let path = format!("/proc/self/fdinfo/{}", self.0.as_raw_fd());
        let fdinfo = fs::read_to_string(path)?;
        if fdinfo_pid(&fdinfo) != Some(pid) {
            return Err(invalid("pidfd does not name the observed process"));
        }
        Ok(())
    }

    pub(super) fn require_live(&self) -> io::Result<()> {
        let mut pollfd = libc::pollfd {
            fd: self.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized pollfd is writable for the duration of the call.
        match unsafe { libc::poll(&mut pollfd, 1, 0) } {
            0 => Ok(()),
            -1 => Err(io::Error::last_os_error()),
            _ => Err(invalid(
                "pidfd is ready; process liveness was not established",
            )),
        }
    }
}

fn fdinfo_pid(fdinfo: &str) -> Option<u32> {
    fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("Pid:"))?
        .trim_ascii()
        .parse::<u32>()
        .ok()
        .filter(|&pid| pid > 0)
}

pub(super) fn peer_credentials(socket: BorrowedFd<'_>) -> io::Result<libc::ucred> {
    let mut creds = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: socket is borrowed for the call; SO_PEERCRED writes a ucred.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut creds as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != size_of::<libc::ucred>() {
        return Err(invalid("invalid socket peer credentials size"));
    }
    Ok(creds)
}

pub(super) fn current_parent() -> u32 {
    // SAFETY: getppid has no memory or ownership requirements.
    unsafe { libc::getppid() as u32 }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Stat {
    pub(super) parent_pid: u32,
    pub(super) start_ticks: u64,
}

impl Stat {
    pub(super) fn read(pid: u32) -> io::Result<Self> {
        let raw = fs::read(format!("/proc/{pid}/stat"))?;
        parse_stat(&raw).ok_or_else(|| invalid("invalid process stat record"))
    }
}

fn parse_stat(raw: &[u8]) -> Option<Stat> {
    // The parenthesized process name can contain non-UTF-8 bytes, spaces, and
    // closing parentheses. The field after its final delimiter is state (3).
    let close = raw.iter().rposition(|&byte| byte == b')')?;
    let mut fields = raw[close + 1..]
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty());
    let parent_pid = str::from_utf8(fields.nth(1)?).ok()?.parse().ok()?;
    let start_ticks = str::from_utf8(fields.nth(17)?).ok()?.parse().ok()?;
    Some(Stat {
        parent_pid,
        start_ticks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_counts_from_the_final_comm_delimiter() {
        let raw =
            b"321 (weird name) \xff) S 123 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 98765 23";
        assert_eq!(
            parse_stat(raw),
            Some(Stat {
                parent_pid: 123,
                start_ticks: 98765
            })
        );
        assert_eq!(parse_stat(b"321 (truncated) S 123"), None);
    }

    #[test]
    fn fdinfo_pid_uses_pid_not_nspid_and_refuses_exited_or_hidden_processes() {
        assert_eq!(
            fdinfo_pid("flags:\t02000002\nPid:\t123\nNSpid:\t123\t1\n"),
            Some(123)
        );
        for fdinfo in ["Pid:\t-1\n", "Pid:\t0\n", "NSpid:\t123\n"] {
            assert_eq!(fdinfo_pid(fdinfo), None);
        }
    }

    #[test]
    fn pidfd_readiness_refuses_a_process_that_exited() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let pid = child.id();
        let fd = PidFd::open(pid);
        let observed = fd.as_ref().map(|fd| fd.require_live());
        child.kill().unwrap();
        child.wait().unwrap();

        observed.unwrap().unwrap();
        let fd = fd.unwrap();
        assert!(fd.require_live().is_err());
        assert!(fd.require_pid(pid).is_err());
    }
}
