use crate::windows::open_process_handle_with_access;
use crate::{file_identity, FileIdentity, ProcessHandleError, RetainedProcessHandle};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::{ffi::OsStringExt, fs::OpenOptionsExt, io::AsRawHandle};
use std::path::{Path, PathBuf};
use windows_sys::Win32::{
    Foundation::{GENERIC_READ, HANDLE, WAIT_TIMEOUT},
    Storage::FileSystem::{FILE_EXECUTE, FILE_SHARE_READ, SYNCHRONIZE},
    System::Threading::{
        QueryFullProcessImageNameW, WaitForSingleObject, PROCESS_QUERY_INFORMATION,
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
}

impl RetainedProcessHandle {
    pub fn image_path(&self) -> io::Result<PathBuf> {
        let mut path = vec![0; 32768];
        let mut len = path.len() as u32;
        // The retained process and writable UTF-16 buffer live through the call.
        if unsafe { QueryFullProcessImageNameW(self.handle, 0, path.as_mut_ptr(), &mut len) } == 0 {
            return Err(io::Error::last_os_error());
        }
        path.truncate(len as usize);
        Ok(PathBuf::from(OsString::from_wide(&path)))
    }

    pub fn process_wait_pending(&self) -> bool {
        // The caller holds the process handle; a zero timeout never waits.
        unsafe { WaitForSingleObject(self.handle, 0) == WAIT_TIMEOUT }
    }

    pub fn image_mapping(&self, file: &LockedImageFile) -> io::Result<ImageMappingReading> {
        let mut handle = file.file().as_raw_handle();
        // The undocumented query reads a HANDLE from this buffer. Both the
        // supplied file handle and the process handle remain owned and open.
        let _status = unsafe {
            NtQueryInformationProcess(
                self.handle,
                PROCESS_IMAGE_FILE_MAPPING,
                (&mut handle as *mut HANDLE).cast(),
                std::mem::size_of::<HANDLE>() as u32,
                std::ptr::null_mut(),
            )
        };
        // NEGATIVE CONTROL ONLY (never merged): admit any opened file, as a path-only check would.
        file_identity(file.file()).map(ImageMappingReading::SameFile)
    }
}
