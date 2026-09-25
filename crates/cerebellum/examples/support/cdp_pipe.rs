//! A minimal client for Chrome's `--remote-debugging-pipe` transport, shared by
//! the probes that launch Chrome themselves rather than through the module.
//!
//! Chrome reads commands from descriptor 3 and writes responses to descriptor
//! 4, each message a JSON object terminated by a NUL byte. A probe that spawns
//! the browser with production's descriptor layout holds the other ends of
//! those two socket pairs and speaks through this type.
//!
//! Included with `#[path = "support/cdp_pipe.rs"] mod cdp_pipe;` at the top
//! level of each probe. Cargo mints example targets from `examples/*.rs` and
//! `examples/*/main.rs` only, so a file here is not built as an example of its
//! own.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Instant;

use serde_json::{json, Value};

/// The CDP pipe: NUL-terminated JSON messages in each direction.
pub struct Cdp {
    writer: UnixStream,
    reader: UnixStream,
    buffer: Vec<u8>,
    next_id: u64,
}

impl Cdp {
    /// `writer` is this side of the pair whose other end the browser reads as
    /// descriptor 3; `reader` is this side of the pair it writes as 4.
    pub fn new(writer: UnixStream, reader: UnixStream) -> Self {
        Self {
            writer,
            reader,
            buffer: Vec::new(),
            next_id: 1,
        }
    }

    /// Write one command without waiting for its answer. Used for
    /// `Browser.close`, whose answer may never arrive because the browser is
    /// already exiting.
    pub fn send(&mut self, method: &str, params: Value) -> Result<u64, String> {
        let id = self.next_id;
        self.next_id += 1;
        let mut bytes = serde_json::to_vec(&json!({"id": id, "method": method, "params": params}))
            .map_err(|error| error.to_string())?;
        bytes.push(0);
        self.writer
            .write_all(&bytes)
            .map_err(|error| format!("write: {error}"))?;
        Ok(id)
    }

    /// Write one command and wait until `deadline` for the answer carrying its
    /// id. Events and answers to other ids that arrive first are discarded.
    pub fn call(
        &mut self,
        method: &str,
        params: Value,
        deadline: Instant,
    ) -> Result<Value, String> {
        let id = self.send(method, params)?;
        loop {
            while let Some(end) = self.buffer.iter().position(|byte| *byte == 0) {
                let frame: Vec<u8> = self.buffer.drain(..=end).collect();
                let Ok(message) = serde_json::from_slice::<Value>(&frame[..end]) else {
                    continue;
                };
                if message["id"].as_u64() == Some(id) {
                    if let Some(error) = message.get("error") {
                        return Err(format!("{method} failed: {error}"));
                    }
                    return Ok(message["result"].clone());
                }
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(format!("{method}: no answer before the deadline"));
            }
            self.reader
                .set_read_timeout(Some(remaining))
                .map_err(|error| error.to_string())?;
            let mut chunk = [0_u8; 64 * 1024];
            match self.reader.read(&mut chunk) {
                Ok(0) => return Err(format!("{method}: the browser closed the pipe")),
                Ok(read) => self.buffer.extend_from_slice(&chunk[..read]),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => return Err(format!("{method}: read: {error}")),
            }
        }
    }
}
