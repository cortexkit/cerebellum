use super::*;
use crate::{file_identity, lock_image_file, ImageMappingReading};
use std::ffi::OsStr;
use std::path::PathBuf;

struct Scratch(PathBuf);

impl Scratch {
    fn new(case: &str) -> Self {
        let path = std::env::temp_dir().join(format!("cereb-launch-{}-{case}", std::process::id()));
        std::fs::create_dir(&path).expect("create isolated fixture directory");
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn shortcut_com_reads_target_and_unexpanded_arguments() {
    let scratch = Scratch::new("shortcut");
    let link = scratch.0.join("Fixture.lnk");
    let target = crate::windows_system_directory().unwrap().join("where.exe");
    let powershell = crate::windows_system_directory()
        .unwrap()
        .join("WindowsPowerShell/v1.0/powershell.exe");
    // System PowerShell only writes a scratch shortcut file; it never starts a
    // browser.
    #[allow(
        clippy::disallowed_methods,
        reason = "runs System32 PowerShell to create a scratch shortcut, never a browser"
    )]
    let status = std::process::Command::new(powershell)
        .args(["-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference = 'Stop'; $sh = New-Object -ComObject WScript.Shell; $link = $sh.CreateShortcut($env:CEREB_TEST_LINK); $link.TargetPath = $env:CEREB_TEST_IMAGE; $link.Arguments = 'fixture argument'; $link.Save()"])
        .env("CEREB_TEST_LINK", &link).env("CEREB_TEST_IMAGE", &target)
        .status().expect("create an isolated shell link");
    assert!(status.success());
    use std::os::windows::fs::OpenOptionsExt;
    let _locked = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&link)
        .unwrap();
    let facts = read_shortcut(&link).expect("read IShellLinkW fields");
    assert!(facts
        .target
        .to_str()
        .unwrap()
        .eq_ignore_ascii_case(target.to_str().unwrap()));
    assert_eq!(facts.arguments, OsStr::new("fixture argument"));
}

#[test]
fn package_com_reads_current_user_registrations() {
    let packages = registered_packages().expect("enumerate packages registered to this user");
    // A service account can legitimately have no registrations. The dedicated
    // fixture test below also reaches the per-package WinRT properties.
    for package in packages {
        let package = package.expect("read package record");
        assert!(package
            .full_name
            .starts_with(package.family.rsplit_once('_').unwrap().0));
        assert!(package.directory.is_absolute());
    }
}

#[test]
#[ignore = "requires a signed package registered for the interactive test user"]
fn package_com_reads_the_provisioned_package_record() {
    let expected = std::env::var("CK_WINDOWS_LAUNCH_PACKAGE_FULL_NAME")
        .expect("fixture's installed package full name");
    let packages = registered_packages().expect("enumerate packages registered to this user");
    let package = packages
        .into_iter()
        .filter_map(Result::ok)
        .find(|package| package.full_name == expected)
        .expect("registered fixture");
    assert!(package.directory.is_absolute());
    assert!(!package.development_mode);
    assert_ne!(package.signature_kind, 0);
}

#[test]
fn appx_com_reads_each_manifest_application() {
    let scratch = Scratch::new("appx");
    std::fs::write(scratch.0.join("AppxManifest.xml"), r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
    xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10" IgnorableNamespaces="uap">
  <Identity Name="CortexKit.LaunchFixture" Publisher="CN=CortexKit Test" Version="1.0.0.0" ProcessorArchitecture="x64" />
  <Properties><DisplayName>Launch fixture</DisplayName><PublisherDisplayName>CortexKit Test</PublisherDisplayName><Logo>Logo.png</Logo></Properties>
  <Dependencies><TargetDeviceFamily Name="Windows.Universal" MinVersion="10.0.19041.0" MaxVersionTested="10.0.22621.0" /></Dependencies>
  <Resources><Resource Language="en-us" /></Resources>
  <Applications>
    <Application Id="First" Executable="First.exe" EntryPoint="LaunchFixture.First">
      <uap:VisualElements DisplayName="First" Description="First" Square150x150Logo="Logo.png" Square44x44Logo="Logo.png" BackgroundColor="transparent" />
    </Application>
    <Application Id="Second" Executable="Second.exe" EntryPoint="LaunchFixture.Second">
      <uap:VisualElements DisplayName="Second" Description="Second" Square150x150Logo="Logo.png" Square44x44Logo="Logo.png" BackgroundColor="transparent" />
    </Application>
  </Applications>
</Package>"#).unwrap();
    let apps = package_applications(&scratch.0).expect("parse package manifest via Appx COM");
    let apps: Vec<_> = apps
        .into_iter()
        .collect::<io::Result<_>>()
        .expect("read each app's attributes");
    assert_eq!(apps.len(), 2);
    assert_eq!((&*apps[0].id, &*apps[0].executable), ("First", "First.exe"));
    assert_eq!(
        (&*apps[1].id, &*apps[1].executable),
        ("Second", "Second.exe")
    );
    assert!(apps[0].aumid.ends_with("!First"));
    assert!(apps[1].aumid.ends_with("!Second"));
}

#[test]
fn suspended_child_keeps_the_loaded_image_and_stays_out_of_jobs() {
    suspended_child(false);
}

#[test]
#[ignore = "requires a runner job that permits breakaway, or a test process outside a job"]
fn suspended_child_proves_positive_breakaway_and_loaded_image() {
    suspended_child(true);
}

fn suspended_child(require_success: bool) {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::{
        Foundation::{
            DuplicateHandle, SetHandleInformation, DUPLICATE_SAME_ACCESS, ERROR_INVALID_HANDLE,
            HANDLE_FLAG_INHERIT,
        },
        System::Threading::{CreateEventW, GetCurrentProcess},
    };
    let current = crate::retain_image_process(std::process::id()).unwrap();
    assert_eq!(current.lifetime_ticks().unwrap().1, None);
    // Keep enough events open to avoid the child's initial system handles
    // landing on the parent's marker value by coincidence.
    let events: Vec<_> = (0..64)
        .map(|_| {
            let event = unsafe { CreateEventW(null(), 0, 0, null()) };
            assert!(!event.is_null());
            unsafe { OwnedHandle::from_raw_handle(event) }
        })
        .collect();
    let marker = events.last().unwrap().as_raw_handle();
    assert_ne!(
        unsafe { SetHandleInformation(marker, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) },
        0
    );
    let path = crate::windows_system_directory().unwrap().join("where.exe");
    let image = lock_image_file(&path).expect("lock read-only system image");
    let suspended = match suspended_process(&image.final_path().unwrap()) {
        Ok(child) => child,
        Err(error) if !require_success && error.kind() == std::io::ErrorKind::PermissionDenied => {
            assert!(
                current.in_job().unwrap(),
                "breakaway denial is only expected in a job: {error}"
            );
            return;
        }
        Err(error) => panic!("start a suspended child: {error}"),
    };
    let child = suspended.process();
    let mut duplicated = null_mut();
    let copied = unsafe {
        DuplicateHandle(
            child.raw_handle(),
            marker,
            GetCurrentProcess(),
            &mut duplicated,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if copied != 0 {
        drop(unsafe { OwnedHandle::from_raw_handle(duplicated) });
        panic!("child has a handle at the inheritable marker's value");
    }
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(ERROR_INVALID_HANDLE as i32)
    );
    assert!(!child.in_job().expect("read job membership"));
    assert_eq!(
        child.image_mapping(&image).unwrap(),
        ImageMappingReading::SameFile(file_identity(image.read_only_handle()).unwrap())
    );
    let scratch = Scratch::new("image-mismatch");
    let copy = scratch.0.join("where.exe");
    std::fs::copy(&path, &copy).unwrap();
    let different = lock_image_file(&copy).unwrap();
    assert!(matches!(
        child.image_mapping(&different).unwrap(),
        ImageMappingReading::NtStatus(_)
    ));
    assert!(process_parents()
        .unwrap()
        .contains(&(child.pid(), std::process::id())));
    // Drop terminates only this suspended child, so no system app runs.
}
