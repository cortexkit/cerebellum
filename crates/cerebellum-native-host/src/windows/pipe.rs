use crate::transport::Transport;
use cerebellum_windows::{
    open_named_pipe_client, wait_named_pipe, OverlappedPipe, ERROR_PIPE_BUSY,
};
use std::cell::Cell;
use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::num::NonZeroU32;
use std::os::windows::io::OwnedHandle;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(super) fn connect(
    name: &OsStr,
    deadline: Instant,
    check_parent: impl FnMut() -> io::Result<()>,
) -> io::Result<PipeConnection> {
    let (handle, timestamp) = connect_with(
        deadline,
        check_parent,
        || open_named_pipe_client(name),
        |remaining| wait_named_pipe(name, remaining),
    )?;
    Ok(PipeConnection::new(handle, timestamp))
}

fn connect_with<T>(
    deadline: Instant,
    mut check_parent: impl FnMut() -> io::Result<()>,
    mut open: impl FnMut() -> io::Result<T>,
    mut wait: impl FnMut(NonZeroU32) -> io::Result<()>,
) -> io::Result<T> {
    loop {
        if Instant::now() >= deadline {
            return Err(connect_timeout());
        }
        // WaitNamedPipe does not reserve the available instance. Re-check the
        // exact launching processes and the deadline before every CreateFile.
        check_parent()?;
        if Instant::now() >= deadline {
            return Err(connect_timeout());
        }
        match open() {
            Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                // Zero selects the pipe's default wait, not a nonblocking
                // check. When less than a whole millisecond remains, stop.
                let timeout =
                    NonZeroU32::new(remaining.as_millis() as u32).ok_or_else(connect_timeout)?;
                wait(timeout)?;
            }
            result => return result,
        }
    }
}

fn connect_timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "cerebellum pipe connect timed out")
}

pub(crate) struct PipeConnection {
    pipe: Arc<OverlappedPipe>,
    timestamp: u64,
    read_deadline: Cell<Option<Instant>>,
    write_timeout: Cell<Option<Duration>>,
}

impl PipeConnection {
    fn new(handle: OwnedHandle, timestamp: u64) -> Self {
        Self {
            pipe: Arc::new(OverlappedPipe::new(handle)),
            timestamp,
            read_deadline: Cell::new(None),
            write_timeout: Cell::new(None),
        }
    }

    pub(super) fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub(super) fn handle(&self) -> io::Result<Arc<OwnedHandle>> {
        self.pipe.handle()
    }

    fn write_deadline(&self) -> Option<Instant> {
        self.write_timeout
            .get()
            .map(|duration| Instant::now() + duration)
    }
}

impl Read for PipeConnection {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.pipe.read(buffer, self.read_deadline.get())
    }
}

impl Write for PipeConnection {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.pipe.write(buffer, self.write_deadline())
    }

    fn write_all(&mut self, mut buffer: &[u8]) -> io::Result<()> {
        let deadline = self.write_deadline();
        while !buffer.is_empty() {
            let sent = self.pipe.write(buffer, deadline)?;
            if sent == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            buffer = &buffer[sent..];
        }
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        // Overlapped writes have already completed. FlushFileBuffers on a
        // pipe can wait indefinitely for the reader to consume those bytes.
        Ok(())
    }
}

impl Transport for PipeConnection {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.read_deadline
            .set(timeout.map(|duration| Instant::now() + duration));
        Ok(())
    }

    fn set_write_timeout(&self, timeout: Duration) -> io::Result<()> {
        self.write_timeout.set(Some(timeout));
        Ok(())
    }

    fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            pipe: self.pipe.clone(),
            timestamp: self.timestamp,
            read_deadline: self.read_deadline.clone(),
            write_timeout: self.write_timeout.clone(),
        })
    }

    fn disconnect(&self) -> io::Result<()> {
        self.pipe.close()
    }
}

#[cfg(all(test, feature = "bridge-test-identities"))]
pub(crate) fn test_pair(buffer_bytes: u32) -> (PipeConnection, PipeConnection) {
    test_pipe(buffer_bytes).1
}

#[cfg(all(test, feature = "bridge-test-identities"))]
fn test_pipe(buffer_bytes: u32) -> (std::ffi::OsString, (PipeConnection, PipeConnection)) {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let name = std::ffi::OsString::from(format!(
        r"\\.\pipe\cknh-conformance-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
    ));
    let peer = cerebellum_windows::create_test_pipe_instance_default_security(&name, buffer_bytes)
        .unwrap();
    let host = connect(
        &name,
        Instant::now() + Duration::from_millis(500),
        || Ok(()),
    )
    .unwrap();
    (name, (host, PipeConnection::new(peer, 0)))
}

#[cfg(test)]
mod tests;
