//! Raw named-pipe operations; connection and authentication policy live in callers.

use std::ffi::OsStr;
use std::io;
use std::num::NonZeroU32;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};
pub use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;
use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, SECURITY_IDENTIFICATION,
    SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::{
    GetNamedPipeClientProcessId, GetNamedPipeServerProcessId, WaitNamedPipeW,
};

mod overlapped;
pub use overlapped::OverlappedPipe;

/// Open a local overlapped pipe client and return the FILETIME sampled before CreateFileW.
pub fn open_named_pipe_client(name: &OsStr) -> io::Result<(OwnedHandle, u64)> {
    let name = wide_name(name)?;
    let connected_at = crate::system_time_100ns();
    // SAFETY: name is NUL-terminated; all optional pointers are null. The
    // flags request duplex overlapped I/O without granting impersonation.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned a new owned handle, not INVALID_HANDLE_VALUE.
    Ok((
        unsafe { OwnedHandle::from_raw_handle(handle) },
        connected_at,
    ))
}

/// Create a fixture-only instance with default security. The production
/// listener supplies its own explicit security descriptor instead.
#[cfg(feature = "bridge-test-identities")]
pub fn create_test_pipe_instance_default_security(
    name: &OsStr,
    buffer_bytes: u32,
) -> io::Result<OwnedHandle> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{CreateNamedPipeW, PIPE_REJECT_REMOTE_CLIENTS};
    let name = wide_name(name)?;
    // SAFETY: name is NUL-terminated. Null security attributes request the
    // process's default DACL and a non-inheritable handle.
    let handle = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_REJECT_REMOTE_CLIENTS,
            1,
            buffer_bytes,
            buffer_bytes,
            0,
            null(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateNamedPipeW returned an independently owned handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

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
