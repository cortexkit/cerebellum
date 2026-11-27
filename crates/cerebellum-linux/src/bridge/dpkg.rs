use std::ffi::CString;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::{ffi::OsStrExt, fs::MetadataExt, fs::OpenOptionsExt};
use std::path::{Component, Path};

use super::invalid;

/// The package fields from one dpkg status stanza, without interpreting its status.
#[derive(Debug)]
pub struct DpkgRecord<'a> {
    pub name: &'a str,
    pub status: &'a str,
    pub architecture: &'a str,
    pub version: &'a str,
}

pub fn read_dpkg_status() -> io::Result<String> {
    let mut status = String::new();
    open_root_file(Path::new("/var/lib/dpkg/status"), libc::O_NONBLOCK)?
        .read_to_string(&mut status)?;
    Ok(status)
}

/// Read the single-line fields from complete stanzas, preserving field values.
pub fn read_dpkg_records(status: &str) -> impl Iterator<Item = DpkgRecord<'_>> {
    status.split("\n\n").filter_map(read_record)
}

fn read_record(stanza: &str) -> Option<DpkgRecord<'_>> {
    let (mut name, mut status, mut architecture, mut version) = (None, None, None, None);
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
            "Status" => &mut status,
            "Architecture" => &mut architecture,
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
    Some(DpkgRecord {
        name: name?,
        status: status?,
        architecture: architecture?,
        version: version?,
    })
}

/// Read whether the indicated dpkg list contains the exact path on its own line.
pub fn read_dpkg_file_list_contains(
    package: &str,
    arch: Option<&str>,
    executable: &Path,
) -> io::Result<bool> {
    let name = match arch {
        Some(arch) => format!("{package}:{arch}.list"),
        None => format!("{package}.list"),
    };
    if name.contains('/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "dpkg list name is not a single filename",
        ));
    }
    let list = Path::new("/var/lib/dpkg/info").join(name);
    let mut contents = Vec::new();
    open_root_file(&list, libc::O_NONBLOCK)?.read_to_end(&mut contents)?;
    Ok(list_contains_path(&contents, executable))
}

fn list_contains_path(list: &[u8], executable: &Path) -> bool {
    list.split(|&byte| byte == b'\n')
        .any(|line| line == executable.as_os_str().as_bytes())
}

/// Open an `O_PATH` handle to a regular file through root-owned, non-writable-by-others paths.
pub fn open_root_image(path: &Path) -> io::Result<File> {
    open_root_file(path, libc::O_PATH)
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

    #[test]
    fn dpkg_record_reads_status_and_version_without_deciding_eligibility() {
        let input = "Package: chromium\nStatus: hold ok installed\nArchitecture: amd64\n\
                     Version: 2:132.0.0-1~deb12u1+test\nDescription: Chromium\n continued\n";
        let record = read_dpkg_records(input).next().unwrap();
        assert_eq!(record.name, "chromium");
        assert_eq!(record.status, "hold ok installed");
        assert_eq!(record.architecture, "amd64");
        assert_eq!(record.version, "2:132.0.0-1~deb12u1+test");
    }

    #[test]
    fn package_list_requires_the_whole_executable_path() {
        let path = Path::new("/opt/google/chrome/chrome");
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
}
