use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, WIN32_ERROR};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE,
    REG_OPTION_NON_VOLATILE, REG_SZ,
};

/// Set the unnamed REG_SZ value of a subkey of HKEY_CURRENT_USER, creating it if needed.
pub fn set_current_user_default_string(subkey: &OsStr, value: &OsStr) -> io::Result<()> {
    let subkey = wide_string(subkey)?;
    let value = wide_string(value)?;
    let bytes = u32::try_from(std::mem::size_of_val(value.as_slice())).map_err(io::Error::other)?;
    let mut key = null_mut();
    // SAFETY: subkey is NUL-terminated, key is writable, and all optional
    // parameters are null. The returned key is owned and requests only set access.
    status(unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            null(),
            &mut key,
            null_mut(),
        )
    })?;
    let key = RegistryKey(key);
    // SAFETY: The key is live; the null name selects the default value and
    // value covers bytes initialized bytes including its terminator.
    status(unsafe { RegSetValueExW(key.0, null(), 0, REG_SZ, value.as_ptr().cast(), bytes) })
}

fn wide_string(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut value: Vec<_> = value.encode_wide().collect();
    if value.contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    value.push(0);
    Ok(value)
}

fn status(code: WIN32_ERROR) -> io::Result<()> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}

struct RegistryKey(HKEY);

impl Drop for RegistryKey {
    fn drop(&mut self) {
        // SAFETY: This wrapper owns the key returned by RegCreateKeyExW.
        unsafe { RegCloseKey(self.0) };
    }
}
