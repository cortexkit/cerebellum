use crate::windows::open_process_handle_with_access;
use crate::{file_identity, FileIdentity, ProcessHandleError, RetainedProcessHandle};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::{ffi::OsStringExt, fs::OpenOptionsExt, io::AsRawHandle};
use std::path::{Path, PathBuf};
use windows_sys::Win32::{
    Foundation::{
        APPMODEL_ERROR_NO_PACKAGE, ERROR_INSUFFICIENT_BUFFER, GENERIC_READ, HANDLE, WAIT_TIMEOUT,
    },
    Storage::{
        FileSystem::{GetFinalPathNameByHandleW, FILE_EXECUTE, FILE_SHARE_READ, SYNCHRONIZE},
        Packaging::Appx::{GetApplicationUserModelId, GetPackageFamilyName, GetPackageFullName},
    },
    System::Threading::{
        GetProcessId, QueryFullProcessImageNameW, WaitForSingleObject, PROCESS_QUERY_INFORMATION,
    },
};

#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(
        process: HANDLE,
        information_class: i32,
        information: *mut std::ffi::c_void,
        information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

// This undocumented information class compares the supplied file object's
// section with the retained process's image; it does not compare pathnames.
const PROCESS_IMAGE_FILE_MAPPING: i32 = 44;

#[derive(Debug, PartialEq, Eq)]
pub enum ImageMappingReading {
    SameFile(FileIdentity),
    NtStatus(i32),
}

#[derive(Debug)]
pub struct LockedImageFile(File);

/// Open a file without sharing writes or deletes. Execute access is required
/// by the kernel's image-mapping query; this operation never executes the file.
pub fn lock_image_file(path: &Path) -> io::Result<LockedImageFile> {
    OpenOptions::new()
        .access_mode(GENERIC_READ | FILE_EXECUTE | SYNCHRONIZE)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .map(LockedImageFile)
}

pub fn retain_image_process(pid: u32) -> Result<RetainedProcessHandle, ProcessHandleError> {
    open_process_handle_with_access(pid, PROCESS_QUERY_INFORMATION | SYNCHRONIZE)
        .map_err(Into::into)
}

impl LockedImageFile {
    pub(crate) fn file(&self) -> &File {
        &self.0
    }

    pub fn read_only_handle(&self) -> &File {
        self.file()
    }

    pub fn final_path(&self) -> io::Result<PathBuf> {
        let mut path = vec![0; 32768];
        // Query the path of the open object, not a separate path lookup.
        let len = unsafe {
            GetFinalPathNameByHandleW(
                self.file().as_raw_handle(),
                path.as_mut_ptr(),
                path.len() as u32,
                0,
            )
        } as usize;
        if len == 0 {
            return Err(io::Error::last_os_error());
        }
        if len >= path.len() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(PathBuf::from(OsString::from_wide(&path[..len])))
    }
}

#[derive(Debug)]
pub struct ProcessPackageFields {
    pub family: String,
    pub aumid: String,
}

impl RetainedProcessHandle {
    pub fn package_full_name(&self) -> io::Result<Option<String>> {
        process_string(self.raw_handle(), GetPackageFullName)
    }

    pub fn pid(&self) -> u32 {
        // This handle remains attached to one process object.
        unsafe { GetProcessId(self.raw_handle()) }
    }

    pub fn package_fields(&self) -> io::Result<Option<ProcessPackageFields>> {
        let Some(family) = process_string(self.raw_handle(), GetPackageFamilyName)? else {
            return Ok(None);
        };
        let aumid = process_string(self.raw_handle(), GetApplicationUserModelId)?
            .ok_or(io::ErrorKind::InvalidData)?;
        Ok(Some(ProcessPackageFields { family, aumid }))
    }

    pub fn image_path(&self) -> io::Result<PathBuf> {
        let mut path = vec![0; 32768];
        let mut len = path.len() as u32;
        // The retained process and writable UTF-16 buffer live through the call.
        if unsafe { QueryFullProcessImageNameW(self.raw_handle(), 0, path.as_mut_ptr(), &mut len) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        path.truncate(len as usize);
        Ok(PathBuf::from(OsString::from_wide(&path)))
    }

    pub fn process_wait_pending(&self) -> bool {
        // The caller holds the process handle; a zero timeout never waits.
        unsafe { WaitForSingleObject(self.raw_handle(), 0) == WAIT_TIMEOUT }
    }

    pub fn image_mapping(&self, file: &LockedImageFile) -> io::Result<ImageMappingReading> {
        let mut handle = file.file().as_raw_handle();
        // The undocumented query reads a HANDLE from this buffer. Both the
        // supplied file handle and the process handle remain owned and open.
        let status = unsafe {
            NtQueryInformationProcess(
                self.raw_handle(),
                PROCESS_IMAGE_FILE_MAPPING,
                (&mut handle as *mut HANDLE).cast(),
                std::mem::size_of::<HANDLE>() as u32,
                std::ptr::null_mut(),
            )
        };
        if status == 0 {
            file_identity(file.file()).map(ImageMappingReading::SameFile)
        } else {
            Ok(ImageMappingReading::NtStatus(status))
        }
    }
}

fn process_string(
    handle: HANDLE,
    read: unsafe extern "system" fn(HANDLE, *mut u32, *mut u16) -> u32,
) -> io::Result<Option<String>> {
    let mut length = 0;
    // These application model APIs report the buffer size in UTF-16 units.
    let status = unsafe { read(handle, &mut length, std::ptr::null_mut()) };
    if status == APPMODEL_ERROR_NO_PACKAGE {
        return Ok(None);
    }
    if status != ERROR_INSUFFICIENT_BUFFER {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if !(2..=1024).contains(&length) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut buffer = vec![0; length as usize];
    // The handle is retained and the writable buffer has the probed size.
    let status = unsafe { read(handle, &mut length, buffer.as_mut_ptr()) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let value = buffer
        .get(..length as usize)
        .and_then(|value| value.strip_suffix(&[0]))
        .ok_or(io::ErrorKind::InvalidData)?;
    if value.is_empty() || value.contains(&0) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    String::from_utf16(value)
        .map(Some)
        .map_err(|_| io::ErrorKind::InvalidData.into())
}
