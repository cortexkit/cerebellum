use std::io;
use std::mem::size_of;
use std::ptr::null_mut;

use tokio::net::windows::named_pipe::NamedPipeServer;
use windows_sys::Win32::Foundation::{LocalFree, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    CreateNamedPipeW, PIPE_ACCEPT_REMOTE_CLIENTS, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

/// Create a non-inheritable, overlapped duplex byte pipe and register it on the
/// current Tokio runtime. Its discretionary access control list (DACL)
/// contains only the supplied security identifiers, each with generic read
/// and write access.
pub fn create_named_pipe_instance(
    name: &str,
    sids: &[&str],
    first: bool,
    reject_remote: bool,
) -> io::Result<NamedPipeServer> {
    if name.contains('\0') || sids.is_empty() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let name: Vec<_> = name.encode_utf16().chain([0]).collect();
    let descriptor = PipeDescriptor::new(sids)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let access = PIPE_ACCESS_DUPLEX
        | FILE_FLAG_OVERLAPPED
        | if first {
            FILE_FLAG_FIRST_PIPE_INSTANCE
        } else {
            0
        };
    let mode = PIPE_TYPE_BYTE
        | PIPE_WAIT
        | if reject_remote {
            PIPE_REJECT_REMOTE_CLIENTS
        } else {
            PIPE_ACCEPT_REMOTE_CLIENTS
        };
    // SAFETY: The terminated pipe name and initialized attributes (including
    // the descriptor) remain live through creation. Windows copies the DACL.
    let handle = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            access,
            mode,
            PIPE_UNLIMITED_INSTANCES,
            65_536,
            65_536,
            0,
            &attributes,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Transfer the fresh, uniquely owned overlapped pipe handle to
    // Tokio, which owns and closes it even if registration fails.
    unsafe { NamedPipeServer::from_raw_handle(handle) }
}

struct PipeDescriptor(PSECURITY_DESCRIPTOR);

impl PipeDescriptor {
    fn new(sids: &[&str]) -> io::Result<Self> {
        let mut sddl = String::from("D:P");
        for sid in sids {
            // Only numeric SID text may enter the expression, never SDDL
            // syntax or an alias. Windows parses the actual SID components.
            if !sid.strip_prefix("S-").is_some_and(|components| {
                components
                    .split('-')
                    .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
            }) {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            sddl.push_str("(A;;GRGW;;;");
            sddl.push_str(sid);
            sddl.push(')');
        }
        let sddl: Vec<_> = sddl.encode_utf16().chain([0]).collect();
        let mut descriptor = null_mut();
        // SAFETY: The input is NUL-terminated UTF-16; `descriptor` is a
        // writable output pointer. The returned allocation uses LocalFree.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }
}

impl Drop for PipeDescriptor {
    fn drop(&mut self) {
        // SAFETY: The descriptor pointer is the live LocalAlloc result.
        unsafe { LocalFree(self.0) };
    }
}
