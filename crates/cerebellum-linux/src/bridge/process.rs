use std::fs::{self, File, Metadata};
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;

use super::invalid;

/// An owned Linux process descriptor.
#[derive(Debug)]
pub struct PidFd(OwnedFd);

impl PidFd {
    pub fn open_process(pid: u32) -> io::Result<Self> {
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

    pub fn open_peer(socket: BorrowedFd<'_>) -> io::Result<Self> {
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

    /// The `Pid:` field as reported by fdinfo, including `-1` or `0`.
    pub fn read_pid(&self) -> io::Result<Option<i32>> {
        let path = format!("/proc/self/fdinfo/{}", self.0.as_raw_fd());
        let fdinfo = fs::read_to_string(path)?;
        Ok(fdinfo_pid(&fdinfo))
    }

    /// Non-blocking poll; true means the descriptor reported an event.
    pub fn read_ready(&self) -> io::Result<bool> {
        let mut pollfd = libc::pollfd {
            fd: self.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized pollfd is writable for the duration of the call.
        match unsafe { libc::poll(&mut pollfd, 1, 0) } {
            0 => Ok(false),
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(true),
        }
    }
}

fn fdinfo_pid(fdinfo: &str) -> Option<i32> {
    fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("Pid:"))?
        .trim_ascii()
        .parse()
        .ok()
}

/// The credentials returned by `SO_PEERCRED`.
#[derive(Debug)]
pub struct PeerCredentials {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

pub fn read_peer_credentials(socket: BorrowedFd<'_>) -> io::Result<PeerCredentials> {
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
    Ok(PeerCredentials {
        pid: creds.pid,
        uid: creds.uid,
        gid: creds.gid,
    })
}

pub fn read_effective_uid() -> u32 {
    // SAFETY: geteuid has no memory or ownership requirements.
    unsafe { libc::geteuid() }
}

pub fn read_parent_pid() -> u32 {
    // SAFETY: getppid has no memory or ownership requirements.
    unsafe { libc::getppid() as u32 }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessStat {
    pub parent_pid: u32,
    pub start_ticks: u64,
}

impl ProcessStat {
    pub fn read(pid: u32) -> io::Result<Self> {
        let raw = fs::read(format!("/proc/{pid}/stat"))?;
        parse_stat(&raw).ok_or_else(|| invalid("invalid process stat record"))
    }
}

fn parse_stat(raw: &[u8]) -> Option<ProcessStat> {
    // The parenthesized process name can contain non-UTF-8 bytes, spaces, and
    // closing parentheses. The field after its final delimiter is state (3).
    let close = raw.iter().rposition(|&byte| byte == b')')?;
    let mut fields = raw[close + 1..]
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty());
    let parent_pid = str::from_utf8(fields.nth(1)?).ok()?.parse().ok()?;
    let start_ticks = str::from_utf8(fields.nth(17)?).ok()?.parse().ok()?;
    Some(ProcessStat {
        parent_pid,
        start_ticks,
    })
}

fn exe_path(pid: u32) -> PathBuf {
    format!("/proc/{pid}/exe").into()
}

/// Open the executable currently named by `/proc/<pid>/exe` for reading.
pub fn open_executable(pid: u32) -> io::Result<File> {
    File::open(exe_path(pid))
}

/// Read the symlink's text, including any kernel-added ` (deleted)` suffix.
pub fn read_executable_path(pid: u32) -> io::Result<PathBuf> {
    fs::read_link(exe_path(pid))
}

/// Stat the current target of the executable link, not the link itself.
pub fn read_executable_metadata(pid: u32) -> io::Result<Metadata> {
    fs::metadata(exe_path(pid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn socket_peer_readings_report_credentials_pidfd_and_image() {
        let (socket, _other) = UnixStream::pair().unwrap();
        let pid = std::process::id();
        let creds = read_peer_credentials(socket.as_fd()).unwrap();
        let pidfd = PidFd::open_peer(socket.as_fd()).unwrap();
        assert_eq!(u32::try_from(creds.pid).unwrap(), pid);
        assert_eq!(creds.uid, read_effective_uid());
        assert_eq!(pidfd.read_pid().unwrap(), Some(creds.pid));
        assert!(!pidfd.read_ready().unwrap());
        assert!(open_executable(pid).unwrap().metadata().unwrap().is_file());
        assert!(read_executable_path(pid).unwrap().is_absolute());
        assert_eq!(
            ProcessStat::read(pid).unwrap().parent_pid,
            read_parent_pid()
        );
    }

    #[test]
    fn stat_counts_from_the_final_comm_delimiter() {
        let raw =
            b"321 (weird name) \xff) S 123 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 98765 23";
        assert_eq!(
            parse_stat(raw),
            Some(ProcessStat {
                parent_pid: 123,
                start_ticks: 98765
            })
        );
        assert_eq!(parse_stat(b"321 (truncated) S 123"), None);
    }

    #[test]
    fn fdinfo_pid_reads_pid_not_nspid_including_exited_or_hidden_values() {
        assert_eq!(
            fdinfo_pid("flags:\t02000002\nPid:\t123\nNSpid:\t123\t1\n"),
            Some(123)
        );
        assert_eq!(fdinfo_pid("Pid:\t-1\n"), Some(-1));
        assert_eq!(fdinfo_pid("Pid:\t0\n"), Some(0));
        assert_eq!(fdinfo_pid("NSpid:\t123\n"), None);
    }

    #[test]
    fn pidfd_readings_report_when_a_process_has_exited() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let pid = child.id();
        let fd = PidFd::open_process(pid);
        let observed = fd.as_ref().map(|fd| fd.read_ready());
        child.kill().unwrap();
        child.wait().unwrap();

        assert!(!observed.unwrap().unwrap());
        let fd = fd.unwrap();
        assert!(fd.read_ready().unwrap());
        assert_eq!(fd.read_pid().unwrap(), Some(-1));
    }
}
