use cerebellum_bridge_protocol::{LinuxBrowser, LinuxPackage, LinuxPackageManager};
use std::ffi::CString;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::{ffi::OsStrExt, fs::MetadataExt, fs::OpenOptionsExt};
use std::path::{Component, Path};

use super::invalid;

#[derive(Clone, Copy)]
struct Browser {
    kind: LinuxBrowser,
    package: &'static str,
    executable: &'static str,
}

const BROWSERS: [Browser; 2] = [
    Browser {
        kind: LinuxBrowser::GoogleChrome,
        package: "google-chrome-stable",
        executable: "/opt/google/chrome/chrome",
    },
    Browser {
        kind: LinuxBrowser::Chromium,
        package: "chromium",
        executable: "/usr/lib/chromium/chromium",
    },
];

pub(super) fn verify_image(path: &Path, image: &File) -> io::Result<(LinuxBrowser, LinuxPackage)> {
    let browser = browser_at_path(path)?;
    let image = image.metadata()?;
    let allowed = open_root_file(Path::new(browser.executable), libc::O_PATH)?.metadata()?;
    if !same_inode(&image, &allowed) {
        return Err(invalid(
            "running browser inode differs from the packaged image",
        ));
    }
    for other in BROWSERS
        .into_iter()
        .filter(|other| other.kind != browser.kind)
    {
        if open_root_file(Path::new(other.executable), libc::O_PATH)
            .and_then(|file| file.metadata())
            .is_ok_and(|other| same_inode(&image, &other))
        {
            return Err(invalid(
                "running browser matches more than one package path",
            ));
        }
    }

    let native_arch = dpkg_architecture(std::env::consts::ARCH)
        .ok_or_else(|| invalid("unsupported native dpkg architecture"))?;
    let mut status = String::new();
    open_root_file(Path::new("/var/lib/dpkg/status"), libc::O_NONBLOCK)?
        .read_to_string(&mut status)?;
    let version = package_version(&status, browser.package, native_arch, |suffix| {
        file_list_contains(browser, suffix)
    })?;

    Ok((
        browser.kind,
        LinuxPackage {
            manager: LinuxPackageManager::Dpkg,
            name: browser.package.to_owned(),
            version,
        },
    ))
}

fn browser_at_path(path: &Path) -> io::Result<Browser> {
    BROWSERS
        .into_iter()
        .find(|browser| path.as_os_str() == browser.executable)
        .ok_or_else(|| invalid("running browser is outside the allowed package paths"))
}

fn same_inode(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn dpkg_architecture(target_arch: &str) -> Option<&'static str> {
    match target_arch {
        "x86_64" => Some("amd64"),
        "aarch64" => Some("arm64"),
        _ => None,
    }
}

fn package_version(
    status: &str,
    package: &str,
    native_arch: &str,
    mut list_contains: impl FnMut(Option<&str>) -> io::Result<bool>,
) -> io::Result<String> {
    let mut lists_path = |suffix| match list_contains(suffix) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        result => result,
    };
    let mut matched = None;
    for stanza in status.split("\n\n") {
        let Some((arch, version)) = installed_record(stanza, package) else {
            continue;
        };
        let listed = lists_path(Some(arch))?
            || ((arch == native_arch || arch == "all") && lists_path(None)?);
        if listed && matched.replace(version).is_some() {
            return Err(invalid("multiple installed dpkg records match the browser"));
        }
    }
    matched
        .map(str::to_owned)
        .ok_or_else(|| invalid("no installed dpkg record lists the browser"))
}

fn installed_record<'a>(stanza: &'a str, package: &str) -> Option<(&'a str, &'a str)> {
    let (mut name, mut state, mut arch, mut version) = (None, None, None, None);
    let mut simple_field = false;
    for line in stanza.lines() {
        if line.starts_with([' ', '\t']) {
            if simple_field {
                return None;
            }
            continue;
        }
        simple_field = false;
        let (key, value) = line.split_once(':')?;
        let slot = match key {
            "Package" => &mut name,
            "Status" => &mut state,
            "Architecture" => &mut arch,
            "Version" => &mut version,
            _ => continue,
        };
        simple_field = true;
        if slot
            .replace(value.trim_start_matches([' ', '\t']))
            .is_some()
        {
            return None;
        }
    }
    let (arch, version) = (arch?, version?);
    if name? != package
        || state? != "install ok installed"
        || arch.is_empty()
        || !arch
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || version.is_empty()
        || version.chars().any(char::is_whitespace)
    {
        return None;
    }
    Some((arch, version))
}

fn file_list_contains(browser: Browser, arch: Option<&str>) -> io::Result<bool> {
    let package = browser.package;
    let list = match arch {
        Some(arch) => format!("/var/lib/dpkg/info/{package}:{arch}.list"),
        None => format!("/var/lib/dpkg/info/{package}.list"),
    };
    let mut contents = Vec::new();
    open_root_file(Path::new(&list), libc::O_NONBLOCK)?.read_to_end(&mut contents)?;
    Ok(list_contains_path(&contents, browser.executable))
}

fn list_contains_path(list: &[u8], executable: &str) -> bool {
    list.split(|&byte| byte == b'\n')
        .any(|line| line == executable.as_bytes())
}

// Walk by held directory handles so metadata checks and subsequent opens
// refer to the same objects, even if an untrusted path component is replaced.
fn open_root_file(path: &Path, final_flags: libc::c_int) -> io::Result<File> {
    let mut components = path.components().peekable();
    if components.next() != Some(Component::RootDir) {
        return Err(invalid("package path is not absolute"));
    }
    let mut dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
        .open("/")?;
    require_root_owned(&dir.metadata()?)?;
    while let Some(Component::Normal(component)) = components.next() {
        let is_final = components.peek().is_none();
        let flags = if is_final {
            final_flags
        } else {
            libc::O_PATH | libc::O_DIRECTORY
        };
        let component = CString::new(component.as_bytes())?;
        // SAFETY: dir is held across the syscall and component is a C string.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                component.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a new, owned descriptor.
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata()?;
        require_root_owned(&metadata)?;
        if is_final {
            if !metadata.is_file() {
                return Err(invalid("package path is not a regular file"));
            }
            return Ok(file);
        }
        dir = file;
    }
    Err(invalid("invalid package path component"))
}

fn require_root_owned(metadata: &Metadata) -> io::Result<()> {
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(invalid(
            "package path is not protected by root ownership and mode",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHROMIUM_RECORD: &str = "Package: chromium\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2:132.0.0-1~deb12u1+test\nDescription: Chromium\n a multiline description\n";

    fn listed_version(status: &str, available_list: Option<&str>) -> io::Result<String> {
        package_version(status, "chromium", "amd64", |list| {
            if list == available_list {
                Ok(true)
            } else {
                Err(io::ErrorKind::NotFound.into())
            }
        })
    }

    #[test]
    fn installed_record_preserves_debian_version_verbatim() {
        let status = format!("Package: other\nStatus: install ok installed\n\n{CHROMIUM_RECORD}\n");
        assert_eq!(
            listed_version(&status, None).unwrap(),
            "2:132.0.0-1~deb12u1+test"
        );
        assert_eq!(
            listed_version(&status, Some("amd64")).unwrap(),
            "2:132.0.0-1~deb12u1+test"
        );
        let upgraded = status.replace("-1~deb12u1", "-1~deb12u2");
        assert_eq!(
            listed_version(&upgraded, None).unwrap(),
            "2:132.0.0-1~deb12u2+test"
        );
    }

    #[test]
    fn noninstalled_missing_or_ambiguous_package_states_refuse() {
        for state in [
            "deinstall ok config-files",
            "install ok unpacked",
            "hold ok installed",
            "install reinstreq installed",
        ] {
            let status = CHROMIUM_RECORD.replace("install ok installed", state);
            assert!(listed_version(&status, None).is_err(), "{state}");
        }
        for malformed in [
            CHROMIUM_RECORD.replace("Package: chromium", "Package: chromium-browser"),
            CHROMIUM_RECORD.replace("Version: 2:132.0.0-1~deb12u1+test\n", ""),
            CHROMIUM_RECORD.replace("Architecture: amd64", "Architecture: ../../amd64"),
            CHROMIUM_RECORD.replace(
                "Architecture: amd64",
                "Architecture: arm64\nArchitecture: amd64",
            ),
            format!("{CHROMIUM_RECORD}\n{CHROMIUM_RECORD}"),
        ] {
            assert!(listed_version(&malformed, None).is_err(), "{malformed}");
        }
    }

    #[test]
    fn dpkg_architectures_distinguish_suffixed_and_unsuffixed_lists() {
        assert_eq!(dpkg_architecture("x86_64"), Some("amd64"));
        assert_eq!(dpkg_architecture("aarch64"), Some("arm64"));
        assert_eq!(dpkg_architecture("riscv64"), None);

        let arm64 = CHROMIUM_RECORD.replace("Architecture: amd64", "Architecture: arm64");
        assert!(listed_version(&arm64, None).is_err());
        assert!(listed_version(&arm64, Some("amd64")).is_err());
        assert!(listed_version(&arm64, Some("arm64")).is_ok());
        let all = CHROMIUM_RECORD.replace("Architecture: amd64", "Architecture: all");
        assert!(listed_version(&all, None).is_ok());
        assert!(
            package_version(CHROMIUM_RECORD, "chromium", "amd64", |list| {
                Ok(list.is_none())
            })
            .is_ok()
        );

        let denied = package_version(CHROMIUM_RECORD, "chromium", "amd64", |_| {
            Err(io::ErrorKind::PermissionDenied.into())
        });
        assert_eq!(denied.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn package_list_requires_the_whole_executable_path() {
        let path = "/opt/google/chrome/chrome";
        assert!(list_contains_path(
            b"/opt/google/chrome/\xff\n/opt/google/chrome/chrome\n",
            path
        ));
        assert!(!list_contains_path(
            b"/opt/google/chrome/chrome-sandbox\n/opt/google/chrome/chrome_crashpad_handler\n",
            path
        ));
        assert!(!list_contains_path(
            b"/home/user/opt/google/chrome/chrome\n",
            path
        ));
    }

    #[test]
    fn only_the_allowed_main_executable_paths_are_eligible() {
        assert_eq!(
            browser_at_path(Path::new("/opt/google/chrome/chrome"))
                .unwrap()
                .kind,
            LinuxBrowser::GoogleChrome
        );
        assert_eq!(
            browser_at_path(Path::new("/usr/lib/chromium/chromium"))
                .unwrap()
                .kind,
            LinuxBrowser::Chromium
        );
        for path in [
            "/opt/google/chrome/chrome (deleted)",
            "/opt/google/chrome/chrome-sandbox",
            "/opt/google/chrome/chrome_crashpad_handler",
            "/snap/chromium/current/usr/lib/chromium-browser/chrome",
            "/usr/bin/python3",
        ] {
            assert!(browser_at_path(Path::new(path)).is_err(), "{path}");
        }
    }
}
