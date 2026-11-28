use super::com::{status, wide, Apartment, Interface, Raw, TaskString};
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use windows_sys::core::{GUID, HRESULT};
use windows_sys::Win32::{
    Foundation::ERROR_INSUFFICIENT_BUFFER, Storage::Packaging::Appx::GetPackagePathByFullName,
    System::Com::CLSCTX_INPROC_SERVER, UI::Shell::SHCreateStreamOnFileEx,
};

#[link(name = "combase.dll", kind = "raw-dylib", modifiers = "+verbatim")]
extern "system" {
    fn RoInitialize(kind: u32) -> HRESULT;
    fn RoUninitialize();
    fn RoActivateInstance(class: Raw, instance: *mut Raw) -> HRESULT;
    fn WindowsCreateString(source: *const u16, len: u32, out: *mut Raw) -> HRESULT;
    fn WindowsDeleteString(value: Raw) -> HRESULT;
    fn WindowsGetStringRawBuffer(value: Raw, len: *mut u32) -> *const u16;
}

const IPACKAGE_MANAGER: GUID = GUID::from_u128(0x9a7d4b65_5e8f_4fc7_a2e5_7f6925cb8b53);
const IPACKAGE_2: GUID = GUID::from_u128(0xa6612fb6_7688_4ace_95fb_359538e7aa01);
const IPACKAGE_4: GUID = GUID::from_u128(0x65aed1ae_b95b_450c_882b_6255187f397e);
const APPX_FACTORY: GUID = GUID::from_u128(0x5842a140_ff9f_4166_8f5c_62f5b7b0c781);
const IAPPX_FACTORY: GUID = GUID::from_u128(0xbeb94909_e451_438b_b5a7_d79e767b75d8);

struct Runtime;

impl Runtime {
    fn mta() -> io::Result<Self> {
        status(unsafe { RoInitialize(1) })?;
        Ok(Self)
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        unsafe { RoUninitialize() };
    }
}

struct RuntimeString(Raw);

impl RuntimeString {
    fn create(text: &str) -> io::Result<Self> {
        let text: Vec<_> = text.encode_utf16().collect();
        Self::read(|out| unsafe { WindowsCreateString(text.as_ptr(), text.len() as u32, out) })
    }

    fn read(call: impl FnOnce(*mut Raw) -> HRESULT) -> io::Result<Self> {
        let mut out = null_mut();
        status(call(&mut out))?;
        if out.is_null() {
            Err(io::ErrorKind::InvalidData.into())
        } else {
            Ok(Self(out))
        }
    }

    fn text(&self) -> io::Result<String> {
        let mut length = 0;
        let data = unsafe { WindowsGetStringRawBuffer(self.0, &mut length) };
        if data.is_null() || length == 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        String::from_utf16(unsafe { std::slice::from_raw_parts(data, length as usize) })
            .map_err(|_| io::ErrorKind::InvalidData.into())
    }
}

impl Drop for RuntimeString {
    fn drop(&mut self) {
        unsafe { WindowsDeleteString(self.0) };
    }
}

type ObjectRead = unsafe extern "system" fn(Raw, *mut Raw) -> HRESULT;
type FlagRead = unsafe extern "system" fn(Raw, *mut u8) -> HRESULT;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredPackage {
    pub full_name: String,
    pub family: String,
    pub directory: PathBuf,
    pub signature_kind: i32,
    pub development_mode: bool,
}

pub fn registered_packages() -> io::Result<Vec<io::Result<RegisteredPackage>>> {
    let _runtime = Runtime::mta()?;
    let name = RuntimeString::create("Windows.Management.Deployment.PackageManager")?;
    let manager_class = Interface::read(|out| unsafe { RoActivateInstance(name.0, out) })?;
    let manager = manager_class.query(&IPACKAGE_MANAGER)?;
    // IPackageManager (9a7d4b65-5e8f-4fc7-a2e5-7f6925cb8b53),
    // windows.management.deployment.h:10911–10953, slot 12 (empty SID = current user).
    let find: unsafe extern "system" fn(Raw, Raw, *mut Raw) -> HRESULT =
        unsafe { manager.method(12) };
    let packages = Interface::read(|out| unsafe { find(manager.raw(), null_mut(), out) })?;
    // IIterable<Package> (69ad6aa7-0c49-5f27-a5eb-ef4d59467b6d),
    // Windows.ApplicationModel.h:9693–9710, First slot 6.
    let first: ObjectRead = unsafe { packages.method(6) };
    let iter = Interface::read(|out| unsafe { first(packages.raw(), out) })?;
    // IIterator<Package> (0217f069-025c-5ee6-a87f-e782e3b623ae),
    // Windows.ApplicationModel.h:9612–9633, Current 6, HasCurrent 7, MoveNext 8.
    let current: ObjectRead = unsafe { iter.method(6) };
    let has: FlagRead = unsafe { iter.method(7) };
    let next: FlagRead = unsafe { iter.method(8) };
    let mut alive = 0;
    status(unsafe { has(iter.raw(), &mut alive) })?;
    let mut records = Vec::new();
    while alive != 0 {
        let package = Interface::read(|out| unsafe { current(iter.raw(), out) })?;
        match package_record(&package) {
            Ok(Some(record)) => records.push(Ok(record)),
            Ok(None) => (),
            Err(err) => records.push(Err(err)),
        }
        status(unsafe { next(iter.raw(), &mut alive) })?;
    }
    Ok(records)
}

fn package_record(package: &Interface) -> io::Result<Option<RegisteredPackage>> {
    // IPackage (163c792f-bd75-413c-bf23-b1fe7b95d825), Windows.ApplicationModel.h:
    // 12735–12756, Id slot 6 and IsFramework slot 8.
    let id: ObjectRead = unsafe { package.method(6) };
    let framework: FlagRead = unsafe { package.method(8) };
    if flag(package, framework)? {
        return Ok(None);
    }
    let package2 = package.query(&IPACKAGE_2)?;
    // IPackage2 (a6612fb6-7688-4ace-95fb-359538e7aa01), Windows.ApplicationModel.h:
    // 4168–4192, IsResourcePackage slot 10, IsBundle 11, IsDevelopmentMode 12.
    let resource: FlagRead = unsafe { package2.method(10) };
    let bundle: FlagRead = unsafe { package2.method(11) };
    let development: FlagRead = unsafe { package2.method(12) };
    if flag(&package2, resource)? || flag(&package2, bundle)? {
        return Ok(None);
    }
    let package4 = package.query(&IPACKAGE_4)?;
    // IPackage4 (65aed1ae-b95b-450c-882b-6255187f397e), Windows.ApplicationModel.h:
    // 4260–4266, SignatureKind slot 6.
    let signature: unsafe extern "system" fn(Raw, *mut i32) -> HRESULT =
        unsafe { package4.method(6) };
    let mut signature_kind = 0;
    status(unsafe { signature(package4.raw(), &mut signature_kind) })?;
    let id = Interface::read(|out| unsafe { id(package.raw(), out) })?;
    // IPackageId (1adb665e-37c7-4790-9980-dd7ae74e8bb2), Windows.ApplicationModel.h:
    // 14561–14593, FullName slot 12 and FamilyName 13.
    let full_name: ObjectRead = unsafe { id.method(12) };
    let family: ObjectRead = unsafe { id.method(13) };
    let full_name = RuntimeString::read(|out| unsafe { full_name(id.raw(), out) })?.text()?;
    let family = RuntimeString::read(|out| unsafe { family(id.raw(), out) })?.text()?;
    Ok(Some(RegisteredPackage {
        directory: package_directory(&full_name)?,
        full_name,
        family,
        signature_kind,
        development_mode: flag(&package2, development)?,
    }))
}

fn flag(object: &Interface, call: FlagRead) -> io::Result<bool> {
    let mut value = 0;
    status(unsafe { call(object.raw(), &mut value) })?;
    Ok(value != 0)
}

fn package_directory(full_name: &str) -> io::Result<PathBuf> {
    let name = wide(OsStr::new(full_name))?;
    let mut length = 0;
    let first = unsafe { GetPackagePathByFullName(name.as_ptr(), &mut length, null_mut()) };
    if first != ERROR_INSUFFICIENT_BUFFER {
        return Err(io::Error::from_raw_os_error(first as i32));
    }
    if !(2..32768).contains(&length) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut buffer = vec![0; length as usize];
    let read = unsafe { GetPackagePathByFullName(name.as_ptr(), &mut length, buffer.as_mut_ptr()) };
    if read != 0 {
        return Err(io::Error::from_raw_os_error(read as i32));
    }
    let value = buffer
        .get(..length as usize)
        .and_then(|value| value.strip_suffix(&[0]))
        .ok_or(io::ErrorKind::InvalidData)?;
    Ok(PathBuf::from(OsString::from_wide(value)))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageApplication {
    pub id: String,
    pub aumid: String,
    pub executable: String,
}

pub fn package_applications(directory: &Path) -> io::Result<Vec<io::Result<PackageApplication>>> {
    let _apartment = Apartment::mta()?;
    let factory = Interface::create(&APPX_FACTORY, &IAPPX_FACTORY, CLSCTX_INPROC_SERVER)?;
    let path = wide(directory.join("AppxManifest.xml").as_os_str())?;
    // STGM_READ | STGM_SHARE_DENY_WRITE; this call only reads the manifest file.
    let stream = Interface::read(|out| unsafe {
        SHCreateStreamOnFileEx(path.as_ptr(), 0x20, 0, 0, null_mut(), out)
    })?;
    // IAppxFactory (beb94909-e451-438b-b5a7-d79e767b75d8), AppxPackaging.h:990–1011,
    // CreateManifestReader slot 5.
    let manifest: unsafe extern "system" fn(Raw, Raw, *mut Raw) -> HRESULT =
        unsafe { factory.method(5) };
    let reader = Interface::read(|out| unsafe { manifest(factory.raw(), stream.raw(), out) })?;
    // IAppxManifestReader (4e1bd148-55a0-4480-a3d1-15544710637c),
    // AppxPackaging.h:3076–3112, GetApplications slot 10.
    let list: ObjectRead = unsafe { reader.method(10) };
    let applications = Interface::read(|out| unsafe { list(reader.raw(), out) })?;
    // IAppxManifestApplicationsEnumerator (9eb8a55a-f04b-4d0d-808d-686185d4847a),
    // AppxPackaging.h:6852–6866, GetCurrent 3, GetHasCurrent 4, MoveNext 5.
    let current: ObjectRead = unsafe { applications.method(3) };
    let has: unsafe extern "system" fn(Raw, *mut i32) -> HRESULT =
        unsafe { applications.method(4) };
    let next: unsafe extern "system" fn(Raw, *mut i32) -> HRESULT =
        unsafe { applications.method(5) };
    let mut alive = 0;
    status(unsafe { has(applications.raw(), &mut alive) })?;
    let mut entries = Vec::new();
    while alive != 0 {
        let app = Interface::read(|out| unsafe { current(applications.raw(), out) })?;
        entries.push(application_fields(&app));
        status(unsafe { next(applications.raw(), &mut alive) })?;
    }
    Ok(entries)
}

fn application_fields(app: &Interface) -> io::Result<PackageApplication> {
    // IAppxManifestApplication (5da89bf4-3773-46be-b650-7e744863b7e8),
    // AppxPackaging.h:6965–6977, GetStringValue slot 3 and GetAppUserModelId slot 4.
    let string: unsafe extern "system" fn(Raw, *const u16, *mut *mut u16) -> HRESULT =
        unsafe { app.method(3) };
    let model: unsafe extern "system" fn(Raw, *mut *mut u16) -> HRESULT = unsafe { app.method(4) };
    let get = |key: &str| {
        let key = wide(OsStr::new(key))?;
        TaskString::read(|out| unsafe { string(app.raw(), key.as_ptr(), out) })?.text()
    };
    let aumid = TaskString::read(|out| unsafe { model(app.raw(), out) })?.text()?;
    Ok(PackageApplication {
        id: get("Id")?,
        aumid,
        executable: get("Executable")?,
    })
}
