use crate::{LinuxBrowser, LinuxPackage, LinuxPackageManager};
use cerebellum_linux::bridge::{
    open_root_image, read_dpkg_file_list_contains, read_dpkg_records, read_dpkg_status,
};
use std::fs::{File, Metadata};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

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
    let allowed = open_root_image(Path::new(browser.executable))?.metadata()?;
    if !same_inode(&image, &allowed) {
        return Err(invalid(
            "running browser inode differs from the packaged image",
        ));
    }
    for other in BROWSERS
        .into_iter()
        .filter(|other| other.kind != browser.kind)
    {
        if open_root_image(Path::new(other.executable))
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
    let status = read_dpkg_status()?;
    let version = package_version(&status, browser.package, native_arch, |suffix| {
        read_dpkg_file_list_contains(browser.package, suffix, Path::new(browser.executable))
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
    for record in read_dpkg_records(status) {
        let arch = record.architecture;
        let version = record.version;
        if record.name != package
            || record.status != "install ok installed"
            || arch.is_empty()
            || !arch
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || version.is_empty()
            || version.chars().any(char::is_whitespace)
        {
            continue;
        }
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
