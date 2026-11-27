use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;
use windows_sys::Win32::Foundation::{
    ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_NOT_FOUND, ERROR_NO_DATA, ERROR_OPERATION_ABORTED,
    ERROR_PIPE_NOT_CONNECTED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject, INFINITE};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

/// Own one overlapped pipe. Concurrent operations use independent events.
/// Operations borrow their buffers until the kernel has completed them,
/// including after cancellation.
pub struct OverlappedPipe(Mutex<Option<Arc<OwnedHandle>>>);

impl OverlappedPipe {
    pub fn new(handle: OwnedHandle) -> Self {
        Self(Mutex::new(Some(Arc::new(handle))))
    }

    pub fn handle(&self) -> io::Result<Arc<OwnedHandle>> {
        self.lock()?.clone().ok_or_else(disconnected)
    }

    pub fn read(&self, buffer: &mut [u8], deadline: Option<Instant>) -> io::Result<usize> {
        match self.transfer(Buffer::Read(buffer), deadline) {
            Err(error) if self.is_disconnected(&error) => Ok(0),
            result => result,
        }
    }

    pub fn write(&self, buffer: &[u8], deadline: Option<Instant>) -> io::Result<usize> {
        self.transfer(Buffer::Write(buffer), deadline)
    }

    pub fn close(&self) -> io::Result<()> {
        // A new operation cannot start after taking the handle out. Existing
        // calls own their handle and drain cancellation before dropping it.
        let Some(handle) = self.lock()?.take() else {
            return Ok(());
        };
        // SAFETY: handle stays live; null selects all pending operations on it.
        if unsafe { CancelIoEx(handle.as_raw_handle(), null()) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_NOT_FOUND as i32) {
                return Err(error);
            }
        }
        Ok(())
    }

    fn lock(&self) -> io::Result<MutexGuard<'_, Option<Arc<OwnedHandle>>>> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("pipe state lock poisoned"))
    }

    fn is_disconnected(&self, error: &io::Error) -> bool {
        match error.raw_os_error().map(|code| code as u32) {
            Some(ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED) => true,
            Some(ERROR_OPERATION_ABORTED) => self.lock().is_ok_and(|handle| handle.is_none()),
            _ => error.kind() == io::ErrorKind::BrokenPipe,
        }
    }

    fn transfer(&self, buffer: Buffer<'_>, deadline: Option<Instant>) -> io::Result<usize> {
        if buffer.len() == 0 {
            return Ok(0);
        }
        if deadline.is_some_and(|end| Instant::now() >= end) {
            return Err(io::ErrorKind::TimedOut.into());
        }
        // SAFETY: All optional pointers are null; this creates an unnamed,
        // non-inheritable, initially unsignaled manual-reset event.
        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: success transferred ownership of the new event.
        let event = unsafe { OwnedHandle::from_raw_handle(event) };
        let mut operation = OVERLAPPED {
            hEvent: event.as_raw_handle(),
            ..Default::default()
        };
        let state = self.lock()?;
        let handle = state.clone().ok_or_else(disconnected)?;
        let pipe = handle.as_raw_handle();
        let mut count = 0;
        let size = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        // SAFETY: handle, event, buffers and operation are live. The lock
        // serializes issuing the request with close(); all pending paths below
        // wait for completion before releasing the stack and caller's buffer.
        let done = unsafe {
            match buffer {
                Buffer::Read(data) => {
                    ReadFile(pipe, data.as_mut_ptr(), size, null_mut(), &mut operation)
                }
                Buffer::Write(data) => {
                    WriteFile(pipe, data.as_ptr(), size, null_mut(), &mut operation)
                }
            }
        };
        if done != 0 {
            // SAFETY: The request completed synchronously, so querying its
            // byte count does not wait or let the kernel keep these pointers.
            if unsafe { GetOverlappedResult(pipe, &operation, &mut count, 0) } == 0 {
                return Err(io::Error::last_os_error());
            }
            return Ok(count as usize);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
            return Err(error);
        }
        drop(state);
        let timeout = deadline.map_or(INFINITE, |end| {
            let remaining = end.saturating_duration_since(Instant::now());
            u32::try_from(remaining.as_nanos().div_ceil(1_000_000))
                .unwrap_or(INFINITE - 1)
                .min(INFINITE - 1)
        });
        // SAFETY: The event belongs only to this operation and stays live.
        let waited = unsafe { WaitForSingleObject(event.as_raw_handle(), timeout) };
        if waited != WAIT_OBJECT_0 {
            let error = if waited == WAIT_TIMEOUT {
                io::ErrorKind::TimedOut.into()
            } else {
                io::Error::last_os_error()
            };
            // SAFETY: Only this operation is cancelled. Completion can race
            // with cancellation, so always reap it before returning.
            unsafe {
                CancelIoEx(pipe, &operation);
                GetOverlappedResult(pipe, &operation, &mut count, 1);
            }
            return Err(error);
        }
        // SAFETY: The operation's event signaled. All pointers and handles
        // still belong to this call, and the operation is complete.
        if unsafe { GetOverlappedResult(pipe, &operation, &mut count, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(count as usize)
    }
}

fn disconnected() -> io::Error {
    io::ErrorKind::BrokenPipe.into()
}

enum Buffer<'a> {
    Read(&'a mut [u8]),
    Write(&'a [u8]),
}

impl Buffer<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Read(data) => data.len(),
            Self::Write(data) => data.len(),
        }
    }
}
