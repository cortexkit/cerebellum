use super::com::{status, wide, Apartment, Interface, Raw, TaskString};
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use windows_sys::core::{GUID, HRESULT};
use windows_sys::Win32::System::Com::CLSCTX_INPROC_SERVER;
use windows_sys::Win32::UI::Shell::{
    FOLDERID_CommonPrograms, FOLDERID_Programs, SHGetKnownFolderPath,
};

const SHELL_LINK: GUID = GUID::from_u128(0x00021401_0000_0000_c000_000000000046);
const ISHELL_LINK_W: GUID = GUID::from_u128(0x000214f9_0000_0000_c000_000000000046);
const IPERSIST_FILE: GUID = GUID::from_u128(0x0000010b_0000_0000_c000_000000000046);
const ACTIVATION_MANAGER: GUID = GUID::from_u128(0x45ba127d_10a8_46ea_8ab7_56ea9078943c);
const IACTIVATION_MANAGER: GUID = GUID::from_u128(0x2e941141_7f97_4756_ba1d_9decde894a3d);

pub fn start_menu_directories() -> [io::Result<PathBuf>; 2] {
    [&FOLDERID_Programs, &FOLDERID_CommonPrograms].map(|id| {
        let path = TaskString::read(|out| unsafe { SHGetKnownFolderPath(id, 0, null_mut(), out) })?;
        Ok(PathBuf::from(OsString::from_wide(path.units())))
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShortcutFields {
    pub target: PathBuf,
    pub arguments: OsString,
}

pub fn read_shortcut(shortcut: &Path) -> io::Result<ShortcutFields> {
    let _apartment = Apartment::mta()?;
    let link = Interface::create(&SHELL_LINK, &ISHELL_LINK_W, CLSCTX_INPROC_SERVER)?;
    let persist = link.query(&IPERSIST_FILE)?;
    let name = wide(shortcut.as_os_str())?;
    // IPersistFile (0000010b-0000-0000-c000-000000000046), ObjIdl.h:12032–12041, Load slot 5.
    let load: unsafe extern "system" fn(Raw, *const u16, u32) -> HRESULT =
        unsafe { persist.method(5) };
    status(unsafe { load(persist.raw(), name.as_ptr(), 0) })?;

    // IShellLinkW (000214f9-0000-0000-c000-000000000046), ShObjIdl_core.h:13764–13808:
    // GetPath slot 3, GetArguments slot 10. Do not call Resolve or expand environment variables.
    let path: unsafe extern "system" fn(Raw, *mut u16, i32, Raw, u32) -> HRESULT =
        unsafe { link.method(3) };
    let args: unsafe extern "system" fn(Raw, *mut u16, i32) -> HRESULT = unsafe { link.method(10) };
    let mut target = vec![0; 32768];
    let mut arguments = vec![0; 32768];
    status(unsafe {
        path(
            link.raw(),
            target.as_mut_ptr(),
            target.len() as i32,
            null_mut(),
            4,
        )
    })?;
    status(unsafe { args(link.raw(), arguments.as_mut_ptr(), arguments.len() as i32) })?;
    Ok(ShortcutFields {
        target: PathBuf::from(read_buffer(&target)?),
        arguments: read_buffer(&arguments)?,
    })
}

fn read_buffer(buffer: &[u16]) -> io::Result<OsString> {
    let end = buffer
        .iter()
        .position(|&unit| unit == 0)
        .filter(|&end| end < buffer.len() - 1)
        .ok_or(io::ErrorKind::InvalidData)?;
    Ok(OsString::from_wide(&buffer[..end]))
}

pub fn activate_application(aumid: &str) -> io::Result<u32> {
    // All interface owners have named bindings and drop before the apartment.
    let _apartment = Apartment::mta()?;
    let manager = Interface::create(
        &ACTIVATION_MANAGER,
        &IACTIVATION_MANAGER,
        CLSCTX_INPROC_SERVER,
    )?;
    activate(&manager, aumid)
}

fn activate(manager: &Interface, aumid: &str) -> io::Result<u32> {
    let name = wide(OsStr::new(aumid))?;
    // IApplicationActivationManager (2e941141-7f97-4756-ba1d-9decde894a3d),
    // ShObjIdl_core.h:31579–31591, ActivateApplication slot 3. AO_NOERRORUI, no arguments.
    let call: unsafe extern "system" fn(Raw, *const u16, *const u16, u32, *mut u32) -> HRESULT =
        unsafe { manager.method(3) };
    let mut pid = 0;
    status(unsafe { call(manager.raw(), name.as_ptr(), null(), 2, &mut pid) })?;
    if pid == 0 {
        Err(io::ErrorKind::InvalidData.into())
    } else {
        Ok(pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires a logged-on shell user with a reachable ApplicationActivationManager COM server"]
    fn activation_manager_rejects_an_unregistered_application() {
        let _apartment = Apartment::mta().unwrap();
        let manager = Interface::create(
            &ACTIVATION_MANAGER,
            &IACTIVATION_MANAGER,
            CLSCTX_INPROC_SERVER,
        )
        .expect("create IApplicationActivationManager in the test user's session");
        let error = activate(
            &manager,
            "CortexKit.UnregisteredFixture_0123456789abc!Missing",
        )
        .unwrap_err();
        assert!(
            error.raw_os_error().is_some(),
            "expected an HRESULT from ActivateApplication: {error:?}"
        );
    }
}
