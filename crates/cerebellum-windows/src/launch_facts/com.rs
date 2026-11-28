use std::ffi::{c_void, OsStr};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null_mut, NonNull};
use windows_sys::core::{GUID, HRESULT};
use windows_sys::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, COINIT_MULTITHREADED,
};

pub(super) type Raw = *mut c_void;

pub(super) fn status(hr: HRESULT) -> io::Result<()> {
    if hr >= 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(hr))
    }
}

pub(super) fn wide(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut value: Vec<_> = value.encode_wide().collect();
    if value.contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    value.push(0);
    Ok(value)
}

pub(super) struct Apartment;

impl Apartment {
    pub(super) fn mta() -> io::Result<Self> {
        status(unsafe { CoInitializeEx(null_mut(), COINIT_MULTITHREADED as u32) })?;
        Ok(Self)
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

pub(super) struct Interface(NonNull<c_void>);

impl Interface {
    pub(super) fn read(call: impl FnOnce(*mut Raw) -> HRESULT) -> io::Result<Self> {
        let mut pointer = null_mut();
        status(call(&mut pointer))?;
        NonNull::new(pointer)
            .map(Self)
            .ok_or_else(|| io::ErrorKind::InvalidData.into())
    }

    pub(super) fn create(class: &GUID, iid: &GUID, context: u32) -> io::Result<Self> {
        Self::read(|out| unsafe { CoCreateInstance(class, null_mut(), context, iid, out) })
    }

    pub(super) fn query(&self, iid: &GUID) -> io::Result<Self> {
        // IUnknown (00000000-0000-0000-C000-000000000046), Unknwn.h:
        // QueryInterface is slot 0; Release (below) is slot 2.
        let call: unsafe extern "system" fn(Raw, *const GUID, *mut Raw) -> HRESULT =
            unsafe { self.method(0) };
        Self::read(|out| unsafe { call(self.raw(), iid, out) })
    }

    pub(super) fn raw(&self) -> Raw {
        self.0.as_ptr()
    }

    // The caller names the exact SDK interface, slot and matching function type.
    pub(super) unsafe fn method<T: Copy>(&self, slot: usize) -> T {
        let vtable = unsafe { *self.raw().cast::<*const T>() };
        unsafe { *vtable.add(slot) }
    }
}

impl Drop for Interface {
    fn drop(&mut self) {
        let release: unsafe extern "system" fn(Raw) -> u32 = unsafe { self.method(2) };
        unsafe { release(self.raw()) };
    }
}

pub(super) struct TaskString(NonNull<u16>);

impl TaskString {
    pub(super) fn read(call: impl FnOnce(*mut *mut u16) -> HRESULT) -> io::Result<Self> {
        let mut pointer = null_mut();
        status(call(&mut pointer))?;
        NonNull::new(pointer)
            .map(Self)
            .ok_or_else(|| io::ErrorKind::InvalidData.into())
    }

    pub(super) fn units(&self) -> &[u16] {
        let ptr = self.0.as_ptr();
        // COM supplies a NUL-terminated CoTaskMem string.
        let len = (0..).take_while(|&i| unsafe { *ptr.add(i) } != 0).count();
        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    pub(super) fn text(&self) -> io::Result<String> {
        String::from_utf16(self.units()).map_err(|_| io::ErrorKind::InvalidData.into())
    }
}

impl Drop for TaskString {
    fn drop(&mut self) {
        unsafe { CoTaskMemFree(self.0.as_ptr().cast()) };
    }
}
