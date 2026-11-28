use super::*;
use crate::pe_product::tests::fixture_versioned_image;
use std::fs::{self, OpenOptions};
use std::os::windows::fs::{symlink_file, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use windows_sys::Wdk::Storage::FileSystem::NtSetSecurityObject;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::PROTECTED_DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
};

const APPLICATION: &str = "Application";
const IMAGE: &str = r"Application\chrome.exe";
const VERSION: &str = r"Application\143.1.55.706";
const DLL: &str = r"Application\143.1.55.706\chrome.dll";
const BROKEN: &str = r"Application\unreadable-acl.dll";
const READ_EXECUTE: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;

struct Fixture {
    root: PathBuf,
    user: String,
    acl_handles: Vec<(PathBuf, File)>,
}

impl Fixture {
    fn new() -> Self {
        Self::with_version_dir(true)
    }

    fn with_version_dir(version_dir: bool) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "ck-writability-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let mut fixture = Self {
            root: fs::canonicalize(root).unwrap(),
            user: crate::current_process_token_user_sid().unwrap(),
            acl_handles: Vec::new(),
        };
        fs::create_dir(fixture.root.join(APPLICATION)).unwrap();
        fixture.retain_acl_handle(APPLICATION);
        fs::write(fixture.root.join(IMAGE), fixture_versioned_image()).unwrap();
        fixture.retain_acl_handle(IMAGE);
        fixture.set(IMAGE, READ_EXECUTE);
        if version_dir {
            fs::create_dir(fixture.root.join(VERSION)).unwrap();
            fixture.retain_acl_handle(VERSION);
            fixture.file(DLL);
        }
        fixture
    }

    fn retain_acl_handle(&mut self, relative: impl AsRef<Path>) {
        let handle = OpenOptions::new()
            .access_mode(WRITE_DAC)
            .share_mode(SHARE_ALL)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(self.root.join(relative.as_ref()))
            .unwrap();
        self.acl_handles
            .push((relative.as_ref().to_owned(), handle));
    }

    fn set(&self, relative: &str, rights: u32) {
        let (_, handle) = self
            .acl_handles
            .iter()
            .find(|(path, _)| path == Path::new(relative))
            .unwrap();
        set_acl(handle, &self.user, rights).unwrap();
    }

    fn file(&mut self, relative: &str) {
        fs::write(self.root.join(relative), b"fixture").unwrap();
        self.retain_acl_handle(relative);
        set_acl(
            &self.acl_handles.last().unwrap().1,
            &self.user,
            READ_EXECUTE,
        )
        .unwrap();
    }

    fn protect_directories(&self) {
        self.set(APPLICATION, READ_EXECUTE);
        self.set(VERSION, READ_EXECUTE);
    }

    fn measure(&self) -> InstallWritability {
        let image = HeldExecutable::open(&self.root.join(IMAGE)).unwrap();
        inspect_install(&image)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let mut cleanup = Ok(());
        for (_, handle) in &self.acl_handles {
            cleanup = cleanup.and(set_acl(handle, &self.user, FILE_ALL_ACCESS));
        }
        self.acl_handles.clear();
        cleanup = cleanup.and(fs::remove_dir_all(&self.root));
        if !std::thread::panicking() {
            cleanup.unwrap();
        }
    }
}

fn set_acl(handle: &File, user: &str, rights: u32) -> io::Result<()> {
    // Owner Rights suppresses the owner's implicit WRITE_DAC. Both application
    // package groups have the same read/execute permissions on every fixture.
    let sddl: Vec<u16> = format!(
        "D:P(A;;0x{rights:x};;;{user})(A;;0x{READ_EXECUTE:x};;;AC)(A;;0x{READ_EXECUTE:x};;;S-1-15-2-2)(A;;0x{rights:x};;;OW)"
    ).encode_utf16().chain([0]).collect();
    let mut descriptor = null_mut();
    // The text is NUL-terminated. The returned descriptor uses LocalFree.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let descriptor = SecurityDescriptor(descriptor);
    // The descriptor and pre-opened WRITE_DAC handle stay live during the call.
    let status = unsafe {
        NtSetSecurityObject(
            handle.as_raw_handle(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor.0,
        )
    };
    if status < 0 {
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32,
        ));
    }
    Ok(())
}

#[test]
fn windows_install_writability_grant_on_directory_only() {
    let fixture = Fixture::new();
    fixture.protect_directories();
    assert_eq!(fixture.measure(), InstallWritability::NotWritable);
    // FILE_ADD_SUBDIRECTORY is deliberately not part of the file-entry mask.
    for path in [APPLICATION, VERSION] {
        fixture.set(path, READ_EXECUTE | FILE_ADD_SUBDIRECTORY);
        assert_eq!(fixture.measure(), InstallWritability::Writable);
        fixture.set(path, READ_EXECUTE);
    }
    assert_eq!(fixture.measure(), InstallWritability::NotWritable);
}

#[test]
fn windows_install_writability_grant_on_dll_only_and_rechecks_after_widening() {
    let fixture = Fixture::new();
    fixture.protect_directories();
    assert_eq!(fixture.measure(), InstallWritability::NotWritable);
    fixture.set(DLL, READ_EXECUTE | FILE_WRITE_DATA);
    assert_eq!(fixture.measure(), InstallWritability::Writable);
    fixture.set(DLL, READ_EXECUTE);
    assert_eq!(fixture.measure(), InstallWritability::NotWritable);
}

#[test]
fn windows_install_writability_grant_supersedes_a_check_error() {
    let mut fixture = Fixture::new();
    fixture.file(BROKEN);
    fixture.protect_directories();
    fixture.set(BROKEN, READ_EXECUTE & !READ_CONTROL);
    assert_eq!(fixture.measure(), InstallWritability::Unknown);
    // The error is in Application; the grant is found later in the version directory.
    fixture.set(DLL, READ_EXECUTE | FILE_WRITE_DATA);
    assert_eq!(fixture.measure(), InstallWritability::Writable);
}

#[test]
fn windows_install_writability_denial_and_check_error_is_unknown() {
    let mut fixture = Fixture::new();
    fixture.file(BROKEN);
    fixture.protect_directories();
    assert_eq!(fixture.measure(), InstallWritability::NotWritable);
    fixture.set(BROKEN, READ_EXECUTE & !READ_CONTROL);
    assert_eq!(fixture.measure(), InstallWritability::Unknown);
}

#[test]
fn windows_install_writability_truncated_enumeration_is_unknown() {
    let mut fixture = Fixture::new();
    // chrome.dll is already one of the version directory's entries.
    for index in 1..4096 {
        fixture.file(&format!(r"{VERSION}\entry-{index:04}.dll"));
    }
    fixture.protect_directories();
    assert_eq!(fixture.measure(), InstallWritability::NotWritable);
    fixture.set(VERSION, READ_EXECUTE | FILE_ADD_FILE);
    fixture.file(&format!(r"{VERSION}\zzz-last.dll"));
    fixture.set(VERSION, READ_EXECUTE);
    assert_eq!(fixture.measure(), InstallWritability::Unknown);
}

#[test]
fn windows_install_writability_missing_version_directory_is_unknown() {
    let fixture = Fixture::with_version_dir(false);
    fixture.set(APPLICATION, READ_EXECUTE);
    assert_eq!(fixture.measure(), InstallWritability::Unknown);
    fixture.set(APPLICATION, READ_EXECUTE | FILE_ADD_SUBDIRECTORY);
    assert_eq!(fixture.measure(), InstallWritability::Writable);
}

#[test]
fn windows_install_writability_checks_reparse_entry_not_target() {
    let mut fixture = Fixture::new();
    let target = fixture.root.join("outside.dll");
    fs::write(&target, b"fixture").unwrap();
    let relative = r"Application\symbolic.dll";
    symlink_file(&target, fixture.root.join(relative)).unwrap();
    fixture.retain_acl_handle(relative);
    fixture.set(relative, READ_EXECUTE);
    fixture.protect_directories();
    assert_eq!(fixture.measure(), InstallWritability::NotWritable);
    fixture.set(relative, READ_EXECUTE | WRITE_DAC);
    assert_eq!(fixture.measure(), InstallWritability::Writable);
}
