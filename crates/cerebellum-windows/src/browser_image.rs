//! Paths and signature readings from Windows image and directory handles.

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::mem::size_of;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;

use windows_sys::core::{w, PCWSTR};
use windows_sys::Win32::Foundation::{GetLastError, ERROR_SUCCESS};
use windows_sys::Win32::Storage::FileSystem::{
    GetFinalPathNameByHandleW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_READ, VOLUME_NAME_GUID,
};
use windows_sys::Win32::System::Registry::{
    RegGetValueW, HKEY_LOCAL_MACHINE, RRF_NOEXPAND, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::QueryFullProcessImageNameW;

use crate::RetainedProcessHandle;

#[cfg(test)]
mod tests;
pub(crate) mod timing;
mod trust;
use timing::measure_image_check;
pub use trust::{
    read_authenticode, read_catalog_signer, read_embedded_root_status, read_product_names,
    AuthenticodeReading, MicrosoftRootReading, SignatureReading, SignerSubject,
};

pub mod image_status {
    pub use windows_sys::Win32::Foundation::{
        CERT_E_REVOCATION_FAILURE, CERT_E_UNTRUSTEDROOT, CRYPT_E_NO_REVOCATION_CHECK,
        CRYPT_E_REVOCATION_OFFLINE, ERROR_SERVICE_NOT_ACTIVE, TRUST_E_BAD_DIGEST,
    };
    pub use windows_sys::Win32::Security::Cryptography::{
        CERT_TRUST_IS_NOT_SIGNATURE_VALID, CERT_TRUST_IS_NOT_TIME_VALID,
        CERT_TRUST_IS_OFFLINE_REVOCATION, CERT_TRUST_IS_REVOKED, CERT_TRUST_IS_UNTRUSTED_ROOT,
        CERT_TRUST_REVOCATION_STATUS_UNKNOWN,
    };
}

const PATH_CAPACITY: usize = 32_768;

#[derive(Debug)]
pub enum ImageReadError {
    QueryImage(u32),
    OpenImage(std::io::Error),
    FinalPath(u32),
    SystemDirectory(u32),
    ProgramFilesRegistry(u32),
    InvalidPath,
    OpenRoot(std::io::Error),
    CatalogOpen(u32),
    CatalogHash(u32),
    CatalogNotFound(u32),
    CatalogInfo(u32),
    TrustStateMissing(i32),
    TrustClose(i32),
    MicrosoftRootApi(u32),
    MissingCertificate,
    CertificateProperty(u32),
    SubjectDecode(u32),
    SubjectEncoding,
}

/// An image opened for reading with neither write nor delete sharing. Its path
/// and signature readings come from that handle, not a second open of the path.
#[derive(Debug)]
pub struct OpenedProcessImage {
    file: File,
    final_path: PathBuf,
}

impl OpenedProcessImage {
    /// Query the retained process, then open the file Windows names. This does
    /// not prove that the named file is the image already mapped in the process.
    pub fn open(process: &RetainedProcessHandle) -> Result<Self, ImageReadError> {
        let path = measure_image_check("QueryFullProcessImageNameW", || {
            let mut path = vec![0u16; PATH_CAPACITY];
            let mut len = path.len() as u32;
            // SAFETY: the process owns a live handle; path and len are writable.
            let ok = unsafe {
                QueryFullProcessImageNameW(process.raw_handle(), 0, path.as_mut_ptr(), &mut len)
            };
            if ok == 0 {
                return Err(ImageReadError::QueryImage(last_error()));
            }
            checked_path(&path, len)
        })?;
        Self::open_path(&path)
    }

    /// Open a path for image readings without asserting it belongs to a process.
    pub fn open_path(path: &Path) -> Result<Self, ImageReadError> {
        let file = measure_image_check("open image file", || {
            OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .open(path)
                .map_err(ImageReadError::OpenImage)
        })?;
        let final_path = final_path(&file)?;
        Ok(Self { file, final_path })
    }

    /// Return the normalized path read from the open file.
    pub fn final_path(&self) -> &Path {
        &self.final_path
    }

    /// Return the existing open file without reopening its path.
    pub fn into_file(self) -> File {
        self.file
    }

    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }
}

/// Retain a directory and the normalized path read from that directory handle.
#[derive(Debug)]
pub struct OpenedMachineDirectory {
    _directory: File,
    final_path: PathBuf,
}

impl OpenedMachineDirectory {
    pub fn final_path(&self) -> &Path {
        &self.final_path
    }
}

pub fn read_system_directory() -> Result<OpenedMachineDirectory, ImageReadError> {
    let path = measure_image_check("GetSystemDirectoryW", || {
        let mut path = vec![0u16; PATH_CAPACITY];
        // SAFETY: path has the specified writable capacity in UTF-16 units.
        let len = unsafe { GetSystemDirectoryW(path.as_mut_ptr(), path.len() as u32) };
        if len == 0 {
            return Err(ImageReadError::SystemDirectory(last_error()));
        }
        checked_path(&path, len)
    })?;
    open_root(&path)
}

#[derive(Clone, Copy, Debug)]
pub enum ProgramFilesDirectory {
    Native,
    X86,
}

pub fn read_program_files_directory(
    which: ProgramFilesDirectory,
) -> Result<OpenedMachineDirectory, ImageReadError> {
    let value: PCWSTR = match which {
        ProgramFilesDirectory::Native => w!("ProgramFilesDir"),
        ProgramFilesDirectory::X86 => w!("ProgramFilesDir (x86)"),
    };
    let mut path = vec![0u16; PATH_CAPACITY];
    let mut bytes = (path.len() * size_of::<u16>()) as u32;
    // SAFETY: the key path and value name are static, terminated strings; path
    // and bytes are a writable buffer and its capacity in bytes.
    let status = measure_image_check("RegGetValueW (Program Files)", || unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            w!(r"SOFTWARE\Microsoft\Windows\CurrentVersion"),
            value,
            RRF_SUBKEY_WOW6464KEY | RRF_RT_REG_SZ | RRF_NOEXPAND,
            null_mut(),
            path.as_mut_ptr().cast(),
            &mut bytes,
        )
    });
    if status != ERROR_SUCCESS {
        return Err(ImageReadError::ProgramFilesRegistry(status));
    }
    let units = bytes / size_of::<u16>() as u32;
    if !bytes.is_multiple_of(2) || units == 0 || path.get(units as usize - 1) != Some(&0) {
        return Err(ImageReadError::InvalidPath);
    }
    open_root(&checked_path(&path, units - 1)?)
}

fn open_root(path: &Path) -> Result<OpenedMachineDirectory, ImageReadError> {
    // A caller's local DOS-device map can shadow a system drive letter. Open
    // trusted machine paths through the global map, not the caller's aliases.
    let mut units = path.as_os_str().encode_wide();
    match (units.next(), units.next(), units.next()) {
        (Some(drive), Some(58), Some(92))
            if u8::try_from(drive).is_ok_and(|d| d.is_ascii_alphabetic()) => {}
        _ => return Err(ImageReadError::InvalidPath),
    }
    let mut global_path = OsString::from(r"\\?\GLOBALROOT\GLOBAL??\");
    global_path.push(path.as_os_str());
    let root = measure_image_check("open machine directory", || {
        OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(global_path)
            .map_err(ImageReadError::OpenRoot)
    })?;
    if !measure_image_check("read machine directory metadata", || root.metadata())
        .map_err(ImageReadError::OpenRoot)?
        .is_dir()
    {
        return Err(ImageReadError::InvalidPath);
    }
    let final_path = final_path(&root)?;
    Ok(OpenedMachineDirectory {
        _directory: root,
        final_path,
    })
}

fn final_path(file: &File) -> Result<PathBuf, ImageReadError> {
    let mut path = vec![0u16; PATH_CAPACITY];
    // SAFETY: the file owns a live handle; path is writable for the specified size.
    // FILE_NAME_NORMALIZED is zero. Use the kernel volume name, not a drive alias.
    let len = measure_image_check("GetFinalPathNameByHandleW", || {
        let len = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                path.as_mut_ptr(),
                path.len() as u32,
                VOLUME_NAME_GUID,
            )
        };
        if len == 0 {
            return Err(ImageReadError::FinalPath(last_error()));
        }
        Ok(len)
    })?;
    checked_path(&path, len)
}

fn checked_path(buffer: &[u16], len: u32) -> Result<PathBuf, ImageReadError> {
    // Successful callers leave room for the terminator and report a length
    // that excludes it. Longer values are requirements, not bytes written.
    if len as usize >= buffer.len() || buffer[len as usize] != 0 {
        return Err(ImageReadError::InvalidPath);
    }
    let units = &buffer[..len as usize];
    let path = PathBuf::from(OsString::from_wide(units));
    if units.contains(&0) || !path.is_absolute() {
        return Err(ImageReadError::InvalidPath);
    }
    Ok(path)
}

fn wide_z(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain([0]).collect()
}

fn last_error() -> u32 {
    // SAFETY: reads the calling thread's failure code.
    unsafe { GetLastError() }
}
