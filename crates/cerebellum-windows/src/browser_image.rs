//! Windows native-messaging image checks, independent of process ancestry.

use std::ffi::{OsStr, OsString};
use std::fmt;
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
mod trust;

const PATH_CAPACITY: usize = 32_768;
const CHROME_RELATIVE: &str = r"Google\Chrome\Application\chrome.exe";

#[derive(Debug)]
pub enum ImageRefusal {
    QueryImage(u32),
    OpenImage(std::io::Error),
    FinalPath(u32),
    SystemDirectory(u32),
    ProgramFilesRegistry(u32),
    InvalidPath,
    OpenRoot(std::io::Error),
    UnexpectedPath,
    CatalogOpen(u32),
    CatalogHash(u32),
    CatalogNotFound(u32),
    CatalogServiceInactive,
    CatalogInfo(u32),
    TrustStateMissing(i32),
    Trust { status: i32, chain_errors: u32 },
    TrustClose(i32),
    MicrosoftRootApi(u32),
    MicrosoftRootPolicy(u32),
    SignerSubject,
    ProductName,
}

impl fmt::Display for ImageRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CatalogServiceInactive => {
                f.write_str("Windows' Cryptographic Services is not running")
            }
            other => write!(f, "Windows image verification refused: {other:?}"),
        }
    }
}

impl std::error::Error for ImageRefusal {}

/// An image opened for reading with neither write nor delete sharing. Its path
/// and verification data come from that handle, not a second open of the path.
#[derive(Debug)]
pub struct OpenedProcessImage {
    file: File,
    final_path: PathBuf,
}

impl OpenedProcessImage {
    /// Query the retained process, then open the file Windows names. This does
    /// not prove that the named file is the image already mapped in the process.
    pub fn open(process: &RetainedProcessHandle) -> Result<Self, ImageRefusal> {
        let mut path = vec![0u16; PATH_CAPACITY];
        let mut len = path.len() as u32;
        // SAFETY: the process owns a live handle; path and len are writable.
        let ok = unsafe {
            QueryFullProcessImageNameW(process.raw_handle(), 0, path.as_mut_ptr(), &mut len)
        };
        if ok == 0 {
            return Err(ImageRefusal::QueryImage(last_error()));
        }
        let path = checked_path(&path, len)?;
        Self::open_path(&path)
    }

    fn open_path(path: &Path) -> Result<Self, ImageRefusal> {
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(path)
            .map_err(ImageRefusal::OpenImage)?;
        let final_path = final_path(&file)?;
        Ok(Self { file, final_path })
    }

    /// Return the same open file for the bridge's signed peer-trailer check.
    pub fn into_file(self) -> File {
        self.file
    }
}

/// Require the system-directory cmd.exe and its Microsoft-rooted SHA-256 catalog.
pub fn verify_system_cmd(image: &OpenedProcessImage) -> Result<(), ImageRefusal> {
    let root = open_root(&system_directory()?)?;
    require_path(image, &root, "cmd.exe")?;
    trust::verify_catalog(image)
}

/// Require a machine-installed Chrome Stable image and its Google signature.
pub fn verify_installed_chrome(image: &OpenedProcessImage) -> Result<(), ImageRefusal> {
    let native_root = open_root(&program_files_directory(w!("ProgramFilesDir"))?)?;
    // Match the native root first: only ask the registry for the second root
    // when the first could not account for the image.
    if !path_matches(image, &native_root, CHROME_RELATIVE)? {
        let x86_root = open_root(&program_files_directory(w!("ProgramFilesDir (x86)"))?)?;
        require_path(image, &x86_root, CHROME_RELATIVE)?;
    }
    trust::verify_chrome(image)
}

fn system_directory() -> Result<PathBuf, ImageRefusal> {
    let mut path = vec![0u16; PATH_CAPACITY];
    // SAFETY: path has the specified writable capacity in UTF-16 units.
    let len = unsafe { GetSystemDirectoryW(path.as_mut_ptr(), path.len() as u32) };
    if len == 0 {
        return Err(ImageRefusal::SystemDirectory(last_error()));
    }
    checked_path(&path, len)
}

fn program_files_directory(value: PCWSTR) -> Result<PathBuf, ImageRefusal> {
    let mut path = vec![0u16; PATH_CAPACITY];
    let mut bytes = (path.len() * size_of::<u16>()) as u32;
    // SAFETY: the key path and value name are static, terminated strings; path
    // and bytes are a writable buffer and its capacity in bytes.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            w!(r"SOFTWARE\Microsoft\Windows\CurrentVersion"),
            value,
            RRF_SUBKEY_WOW6464KEY | RRF_RT_REG_SZ | RRF_NOEXPAND,
            null_mut(),
            path.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(ImageRefusal::ProgramFilesRegistry(status));
    }
    let units = bytes / size_of::<u16>() as u32;
    if !bytes.is_multiple_of(2) || units == 0 || path.get(units as usize - 1) != Some(&0) {
        return Err(ImageRefusal::InvalidPath);
    }
    checked_path(&path, units - 1)
}

fn open_root(path: &Path) -> Result<File, ImageRefusal> {
    // A caller's local DOS-device map can shadow a system drive letter. Open
    // trusted machine paths through the global map, not the caller's aliases.
    let mut units = path.as_os_str().encode_wide();
    match (units.next(), units.next(), units.next()) {
        (Some(drive), Some(58), Some(92))
            if u8::try_from(drive).is_ok_and(|d| d.is_ascii_alphabetic()) => {}
        _ => return Err(ImageRefusal::InvalidPath),
    }
    let mut global_path = OsString::from(r"\\?\GLOBALROOT\GLOBAL??\");
    global_path.push(path.as_os_str());
    let root = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(global_path)
        .map_err(ImageRefusal::OpenRoot)?;
    if !root.metadata().map_err(ImageRefusal::OpenRoot)?.is_dir() {
        return Err(ImageRefusal::InvalidPath);
    }
    Ok(root)
}

fn final_path(file: &File) -> Result<PathBuf, ImageRefusal> {
    let mut path = vec![0u16; PATH_CAPACITY];
    // SAFETY: the file owns a live handle; path is writable for the specified size.
    // FILE_NAME_NORMALIZED is zero. Use the kernel volume name, not a drive alias.
    let len = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            path.as_mut_ptr(),
            path.len() as u32,
            VOLUME_NAME_GUID,
        )
    };
    if len == 0 {
        return Err(ImageRefusal::FinalPath(last_error()));
    }
    checked_path(&path, len)
}

fn checked_path(buffer: &[u16], len: u32) -> Result<PathBuf, ImageRefusal> {
    // Successful callers leave room for the terminator and report a length
    // that excludes it. Longer values are requirements, not bytes written.
    if len as usize >= buffer.len() || buffer[len as usize] != 0 {
        return Err(ImageRefusal::InvalidPath);
    }
    let units = &buffer[..len as usize];
    let path = PathBuf::from(OsString::from_wide(units));
    if units.contains(&0) || !path.is_absolute() {
        return Err(ImageRefusal::InvalidPath);
    }
    Ok(path)
}

fn path_matches(
    image: &OpenedProcessImage,
    root: &File,
    relative: &str,
) -> Result<bool, ImageRefusal> {
    // Exact normalized names also distinguish different files in directories
    // where Windows has case-sensitive lookup enabled.
    Ok(image.final_path.as_os_str() == final_path(root)?.join(relative).as_os_str())
}

fn require_path(
    image: &OpenedProcessImage,
    root: &File,
    relative: &str,
) -> Result<(), ImageRefusal> {
    path_matches(image, root, relative)?
        .then_some(())
        .ok_or(ImageRefusal::UnexpectedPath)
}

fn wide_z(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain([0]).collect()
}

fn last_error() -> u32 {
    // SAFETY: reads the calling thread's failure code.
    unsafe { GetLastError() }
}
