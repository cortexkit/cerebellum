use std::fs::File;
use std::io::{self, Write};

use cerebellum_windows::DevToolsPipeReader;

use crate::browser_launch_readiness::{CdpPipeIo, PipeRead};

/// The parent ends of a Windows DevTools connection. The Windows runtime does
/// not call this adapter or advertise browser tools.
pub struct WindowsCdpPipe {
    command: File,
    response: DevToolsPipeReader,
}

impl WindowsCdpPipe {
    pub fn new(command: File, response: DevToolsPipeReader) -> Self {
        Self { command, response }
    }
}

impl CdpPipeIo for WindowsCdpPipe {
    // Anonymous pipe writes are synchronous. Keep the trait's default refusal
    // for deadline-bounded writes rather than risk blocking teardown.
    fn write_frame(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.command.write_all(bytes)
    }

    fn read(&mut self, destination: &mut [u8]) -> io::Result<PipeRead> {
        if destination.is_empty() {
            return Ok(PipeRead::WouldBlock);
        }
        match self.response.try_read(destination) {
            Ok(0) => Ok(PipeRead::Closed),
            Ok(count) => Ok(PipeRead::Bytes(count)),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(PipeRead::WouldBlock),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests;
