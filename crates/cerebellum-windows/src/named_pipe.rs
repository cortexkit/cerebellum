//! Raw named-pipe operations; connection and authentication policy live in callers.

use std::ffi::OsStr;
use std::io;
use std::num::NonZeroU32;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, BorrowedHandle};
use windows_sys::Win32::System::Pipes::{
    GetNamedPipeClientProcessId, GetNamedPipeServerProcessId, WaitNamedPipeW,
};

pub fn named_pipe_client_pid(pipe: BorrowedHandle<'_>) -> io::Result<u32> {
    let mut pid = 0;
    // SAFETY: the pipe handle is borrowed for the call and pid is writable.
    bool_result(unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle(), &mut pid) })?;
    Ok(pid)
}

pub fn named_pipe_server_pid(pipe: BorrowedHandle<'_>) -> io::Result<u32> {
    let mut pid = 0;
    // SAFETY: the pipe handle is borrowed for the call and pid is writable.
    bool_result(unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) })?;
    Ok(pid)
}

/// Wait for an available pipe instance. A successful wait does not reserve it.
pub fn wait_named_pipe(name: &OsStr, timeout_ms: NonZeroU32) -> io::Result<()> {
    let name = wide_name(name)?;
    // SAFETY: name points to a live NUL-terminated UTF-16 string.
    bool_result(unsafe { WaitNamedPipeW(name.as_ptr(), timeout_ms.get()) })
}

fn wide_name(name: &OsStr) -> io::Result<Vec<u16>> {
    let mut name: Vec<_> = name.encode_wide().collect();
    if name.contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    name.push(0);
    Ok(name)
}

fn bool_result(ok: i32) -> io::Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
