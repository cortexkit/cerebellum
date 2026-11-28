use std::fs::File;
use std::io;
use std::mem::{size_of, MaybeUninit};
use std::os::windows::io::AsRawHandle;
use windows_sys::Win32::Storage::FileSystem::{
    FileIdInfo, GetFileInformationByHandleEx, FILE_ID_INFO,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileIdentity {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

/// Read the kernel's identity for an open file or directory, without walking a path.
pub fn file_identity(file: &File) -> io::Result<FileIdentity> {
    let mut info = MaybeUninit::<FILE_ID_INFO>::uninit();
    // The handle remains valid through the call, and the buffer is a writable
    // FILE_ID_INFO, whose layout and size match the FileIdInfo request.
    let success = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            info.as_mut_ptr().cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    // Windows initializes the buffer on success.
    let info = unsafe { info.assume_init() };
    Ok(FileIdentity {
        volume_serial_number: info.VolumeSerialNumber,
        file_id: info.FileId.Identifier,
    })
}
