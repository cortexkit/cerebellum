use std::io::{self, Read, Write};
use std::time::Duration;

/// A connected, full-duplex transport. Clones share the connection so Chrome's
/// input can be forwarded on a separate thread while the original reads replies.
pub(crate) trait Transport: Read + Write + Send + Sized + 'static {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn set_write_timeout(&self, timeout: Duration) -> io::Result<()>;
    fn try_clone(&self) -> io::Result<Self>;

    /// End both directions, including I/O blocked on another clone. A read
    /// between frames must observe EOF so the relay can report which side closed.
    fn disconnect(&self) -> io::Result<()>;
}

#[cfg(unix)]
impl Transport for std::os::unix::net::UnixStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Duration) -> io::Result<()> {
        self.set_write_timeout(Some(timeout))
    }

    fn try_clone(&self) -> io::Result<Self> {
        self.try_clone()
    }

    fn disconnect(&self) -> io::Result<()> {
        self.shutdown(std::net::Shutdown::Both)
    }
}
