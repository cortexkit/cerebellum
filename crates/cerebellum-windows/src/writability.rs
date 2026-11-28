//! Measure install writability without opening any target for mutation.

use crate::{identity::HeldExecutable, pe_product::read_file_version};
use std::fs::File;
use std::io;
use std::mem::{offset_of, size_of, size_of_val};
use std::os::windows::fs::FileExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    NtCreateFile, FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Win32::Foundation::{
    LocalFree, RtlNtStatusToDosError, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_FILES,
    UNICODE_STRING,
};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    AccessCheck, DuplicateToken, SecurityImpersonation, DACL_SECURITY_INFORMATION, GENERIC_MAPPING,
    GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PRIVILEGE_SET, PSECURITY_DESCRIPTOR,
    TOKEN_DUPLICATE, TOKEN_QUERY,
};
use windows_sys::Win32::Storage::FileSystem::{
    FileAttributeTagInfo, FileFullDirectoryInfo, GetFileInformationByHandleEx, DELETE,
    FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_DELETE_CHILD, FILE_FULL_DIR_INFO,
    FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA,
    READ_CONTROL, SYNCHRONIZE, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

const DIRECTORY_MASK: u32 =
    FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER;
const FILE_MASK: u32 = FILE_WRITE_DATA | DELETE | WRITE_DAC | WRITE_OWNER;
const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
// winnt.h: request the entire granted mask from AccessCheck.
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const ENTRY_LIMIT: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallWritability {
    Writable,
    NotWritable,
    Unknown,
}

/// Check the install beside the held executable, using the current process
/// token (including its elevated groups, if any), not the future child token.
pub fn inspect_install(executable: &HeldExecutable) -> InstallWritability {
    let Ok(token) = impersonation_token() else {
        return InstallWritability::Unknown;
    };
    let version = read_file_version(|mut offset, mut buf| {
        while !buf.is_empty() {
            let n = executable.image().seek_read(buf, offset)?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            offset += n as u64;
            buf = &mut buf[n..];
        }
        Ok(())
    });
    let install = executable.install_directory();
    let mut probe = Probe { incomplete: false };
    if probe.directory(&token, install) {
        return InstallWritability::Writable;
    }
    let version = version.map(|[a, b, c, d]| format!("{a}.{b}.{c}.{d}"));
    if let Some(version_dir) = version.and_then(|name| {
        let dir = open_entry(
            install,
            &name.encode_utf16().collect::<Vec<_>>(),
            FILE_READ_ATTRIBUTES,
        )
        .ok()?;
        ordinary_directory(&dir).ok()?.then_some(dir)
    }) {
        if probe.directory(&token, &version_dir) {
            return InstallWritability::Writable;
        }
    } else {
        probe.incomplete = true;
    }
    if probe.incomplete {
        InstallWritability::Unknown
    } else {
        InstallWritability::NotWritable
    }
}

struct Probe {
    incomplete: bool,
}

impl Probe {
    fn saw_grant(&mut self, check: io::Result<bool>) -> bool {
        match check {
            Ok(granted) => granted,
            Err(_) => {
                self.incomplete = true;
                false
            }
        }
    }

    fn directory(&mut self, token: &OwnedHandle, directory: &File) -> bool {
        // READ_CONTROL and list access are independent. A failure to list a
        // directory must not hide a granted right on the directory itself.
        if self.saw_grant(
            reopen(directory, READ_CONTROL)
                .and_then(|file| access_check(token, &file, DIRECTORY_MASK)),
        ) {
            return true;
        }
        let scanned = reopen(directory, FILE_LIST_DIRECTORY).and_then(|listed| {
            scan_entries(&listed, |name| {
                self.saw_grant(
                    open_entry(directory, name, READ_CONTROL)
                        .and_then(|file| access_check(token, &file, FILE_MASK)),
                )
            })
        });
        match scanned {
            Ok(ScanEnd::Grant) => true,
            Ok(ScanEnd::Complete) => false,
            Ok(ScanEnd::Truncated) | Err(_) => {
                self.incomplete = true;
                false
            }
        }
    }
}

fn impersonation_token() -> io::Result<OwnedHandle> {
    let mut primary = null_mut();
    // The current-process pseudo-handle is valid and the output is writable.
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut primary,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // OpenProcessToken transferred a real handle.
    let primary = unsafe { OwnedHandle::from_raw_handle(primary) };
    let mut duplicate = null_mut();
    // AccessCheck requires an impersonation token but the thread need not impersonate it.
    if unsafe {
        DuplicateToken(
            primary.as_raw_handle(),
            SecurityImpersonation,
            &mut duplicate,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(duplicate) })
}

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // GetSecurityInfo allocates the returned descriptor with LocalAlloc.
        unsafe { LocalFree(self.0) };
    }
}

fn access_check(token: &OwnedHandle, file: &File, mask: u32) -> io::Result<bool> {
    let mut descriptor = null_mut();
    // AccessCheck requires owner and group SIDs as well as the DACL. Request
    // one allocation containing all three; the individual output pointers are optional.
    let result = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    let descriptor = SecurityDescriptor(descriptor);
    let mapping = GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ,
        GenericWrite: FILE_GENERIC_WRITE,
        GenericExecute: FILE_GENERIC_EXECUTE,
        GenericAll: FILE_ALL_ACCESS,
    };
    let mut privileges = vec![PRIVILEGE_SET::default()];
    loop {
        let mut len = size_of_val(privileges.as_slice()) as u32;
        let mut granted = 0;
        let mut access_status = 0;
        // The descriptor and token remain live. The privilege output is
        // aligned and the length describes its full writable capacity.
        if unsafe {
            AccessCheck(
                descriptor.0,
                token.as_raw_handle(),
                MAXIMUM_ALLOWED,
                &mapping,
                privileges.as_mut_ptr(),
                &mut len,
                &mut granted,
                &mut access_status,
            )
        } != 0
        {
            return Ok(access_status != 0 && granted & mask != 0);
        }
        let error = io::Error::last_os_error();
        let required = (len as usize).div_ceil(size_of::<PRIVILEGE_SET>());
        if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
            || required <= privileges.len()
        {
            return Err(error);
        }
        privileges.resize(required, PRIVILEGE_SET::default());
    }
}

fn reopen(file: &File, access: u32) -> io::Result<File> {
    // An empty relative name reopens the held directory itself. Listing uses
    // a synchronous handle with its own enumeration cursor.
    open_relative(file, &[], access)
}

fn open_entry(directory: &File, name: &[u16], access: u32) -> io::Result<File> {
    // Only accept one literal component; relative opens do not traverse links
    // or interpret an alternate stream or a path separator as part of a name.
    if name.is_empty()
        || name
            .iter()
            .any(|unit| matches!(unit, 0 | 0x2f | 0x3a | 0x5c))
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    open_relative(directory, name, access)
}

fn open_relative(directory: &File, name: &[u16], access: u32) -> io::Result<File> {
    let mut name = name.to_vec();
    let bytes =
        u16::try_from(size_of_val(name.as_slice())).map_err(|_| io::ErrorKind::InvalidData)?;
    let name = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: directory.as_raw_handle(),
        ObjectName: &name,
        ..Default::default()
    };
    let mut handle = null_mut();
    let mut status = IO_STATUS_BLOCK::default();
    let (access, options) = if access == FILE_LIST_DIRECTORY {
        (
            access | SYNCHRONIZE,
            FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        )
    } else {
        (access, FILE_OPEN_REPARSE_POINT)
    };
    // The name and status block live through the call. FILE_OPEN_REPARSE_POINT
    // is the native equivalent of FILE_FLAG_OPEN_REPARSE_POINT for this relative open.
    let result = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &attributes,
            &mut status,
            null(),
            0,
            SHARE_ALL,
            FILE_OPEN,
            options,
            null(),
            0,
        )
    };
    if result < 0 {
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(result) } as i32,
        ));
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn ordinary_directory(file: &File) -> io::Result<bool> {
    let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
    // The information class and the writable output structure match.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileAttributeTagInfo,
            (&mut info as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            size_of_val(&info) as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(
        info.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
            == FILE_ATTRIBUTE_DIRECTORY,
    )
}

enum ScanEnd {
    Complete,
    Grant,
    Truncated,
}

fn scan_entries(directory: &File, mut visit: impl FnMut(&[u16]) -> bool) -> io::Result<ScanEnd> {
    // FILE_FULL_DIR_INFO entries are aligned to 8 bytes and linked by offsets.
    const NAME: usize = offset_of!(FILE_FULL_DIR_INFO, FileName);
    let mut buffer = vec![0u64; 4096];
    let mut checked = 0;
    loop {
        buffer.fill(0);
        let size = size_of_val(buffer.as_slice());
        // The handle is dedicated to this scan, so repeated calls continue
        // the same enumeration without sharing its cursor with other uses.
        if unsafe {
            GetFileInformationByHandleEx(
                directory.as_raw_handle(),
                FileFullDirectoryInfo,
                buffer.as_mut_ptr().cast(),
                size as u32,
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                Ok(ScanEnd::Complete)
            } else {
                Err(error)
            };
        }
        // The initialized allocation can be viewed as bytes for checked parsing.
        let mut batch = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), size) };
        loop {
            let field = |offset| -> io::Result<usize> {
                let bytes = batch
                    .get(offset..offset + 4)
                    .ok_or(io::ErrorKind::InvalidData)?;
                Ok(u32::from_ne_bytes(bytes.try_into().unwrap()) as usize)
            };
            let next = field(offset_of!(FILE_FULL_DIR_INFO, NextEntryOffset))?;
            let length = field(offset_of!(FILE_FULL_DIR_INFO, FileNameLength))?;
            let name_end = NAME.checked_add(length).ok_or(io::ErrorKind::InvalidData)?;
            if length == 0
                || length % 2 != 0
                || (next != 0 && (next < name_end || next >= batch.len()))
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let bytes = batch
                .get(NAME..name_end)
                .ok_or(io::ErrorKind::InvalidData)?;
            let name: Vec<u16> = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .copied()
                .map(u16::from_ne_bytes)
                .collect();
            if name != [b'.' as u16] && name != [b'.' as u16; 2] {
                // Observe one extra entry to distinguish exactly 4,096 from
                // truncation, but never open or check that extra entry.
                if checked == ENTRY_LIMIT {
                    return Ok(ScanEnd::Truncated);
                }
                checked += 1;
                if visit(&name) {
                    return Ok(ScanEnd::Grant);
                }
            }
            if next == 0 {
                break;
            }
            batch = &batch[next..];
        }
    }
}

#[cfg(test)]
mod tests;
