//! Descriptor-based Linux desktop app identity. Pids must come from a trusted
//! peer credential source; this module does not discover desktop applications.

use std::collections::{HashMap, VecDeque};
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

use md5::Md5;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

use crate::{process_generation, ProcessGeneration, ProcessGenerationReading};

mod packages;
#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    AppIdentityUnproven,
    PackageChecksumUnavailable,
    InterpreterHostedImage,
    ImageReplacedSinceLaunch,
    ExecutableMappingUnverifiable,
    OperatorAppBlocked,
    StaleReference,
}

impl Refusal {
    pub fn reason(self) -> &'static str {
        match self {
            Self::AppIdentityUnproven => "app_identity_unproven",
            Self::PackageChecksumUnavailable => "package_checksum_unavailable",
            Self::InterpreterHostedImage => "interpreter_hosted_image",
            Self::ImageReplacedSinceLaunch => "image_replaced_since_launch",
            Self::ExecutableMappingUnverifiable => "executable_mapping_unverifiable",
            Self::OperatorAppBlocked => "operator_app_blocked",
            Self::StaleReference => "stale_reference",
        }
    }
}

use Refusal::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedApp {
    pub generation: ProcessGeneration,
    pub exe_device: u64,
    pub exe_inode: u64,
    pub path: PathBuf,
    pub subject: String,
}

impl VerifiedApp {
    pub fn generation_evidence(&self) -> String {
        generation_evidence(self.generation, self.exe_device, self.exe_inode)
    }

    pub fn display_name(&self, registered_name: Option<&str>) -> String {
        let name = registered_name.map(str::to_owned).unwrap_or_else(|| {
            self.path
                .file_name()
                .unwrap_or(self.path.as_os_str())
                .to_string_lossy()
                .into_owned()
        });
        if self.subject.starts_with("sha256:") {
            format!("{name} ({}; no supported package manager has a verified record of this image; permission is tied to its image digest)", self.path.display())
        } else {
            name
        }
    }
}

pub fn is_subject(target: &str) -> bool {
    ["dpkg:", "rpm:", "snap:", "sha256:"]
        .iter()
        .any(|prefix| target.starts_with(prefix))
}

pub fn is_package_subject(subject: &str) -> bool {
    subject.split_once(':').is_some_and(|(scheme, package)| {
        matches!(scheme, "dpkg" | "rpm" | "snap")
            && !package.is_empty()
            && package
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-' | b'_'))
    })
}

/// The desktop session owns these caches, so rebuilding a driver does not
/// drop them. Each proof still checks procfs, paths, mounts and package records.
#[derive(Debug, Default)]
pub struct IdentityReader {
    digests: Mutex<DigestCache>,
    packages: Mutex<packages::Database>,
}

impl IdentityReader {
    pub fn reprove(
        &self,
        pid: u32,
        expected_generation: &str,
        subject: &str,
    ) -> Result<VerifiedApp, Refusal> {
        let started = generation(pid)?;
        let image = fs::metadata(format!("/proc/{pid}/exe")).map_err(|_| StaleReference)?;
        if generation_evidence(started, image.dev(), image.ino()) != expected_generation {
            return Err(StaleReference);
        }
        let app = self.prove(pid)?;
        if app.generation_evidence() != expected_generation {
            return Err(StaleReference);
        }
        if app.subject != subject {
            return Err(if is_package_subject(subject) {
                ImageReplacedSinceLaunch
            } else {
                StaleReference
            });
        }
        Ok(app)
    }

    pub fn prove(&self, pid: u32) -> Result<VerifiedApp, Refusal> {
        let proc = PathBuf::from(format!("/proc/{pid}"));
        let root_path = proc.join("root");
        check_flatpak(&proc, &root_path)?;

        let started = generation(pid)?;
        let exe_path = proc.join("exe");
        let mut exe = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&exe_path)
            .map_err(|_| AppIdentityUnproven)?;
        let metadata = exe.metadata().map_err(|_| AppIdentityUnproven)?;
        let path = fs::read_link(fd_path(&exe)).map_err(|_| AppIdentityUnproven)?;
        let key = image_key(&metadata);
        check_exe(&path, &metadata)?;

        let root = open_path(&root_path).map_err(|_| ExecutableMappingUnverifiable)?;
        let mounts = Mounts::read(&proc)?;
        let leaf = walk(&root, &path, false).map_err(|_| ExecutableMappingUnverifiable)?;
        if !same_file(
            &metadata,
            &leaf.metadata().map_err(|_| ExecutableMappingUnverifiable)?,
        ) {
            return Err(ImageReplacedSinceLaunch);
        }
        let exe_mount = mounts.trusted_mount(&leaf)?;
        if mount_id(&exe).map_err(|_| ExecutableMappingUnverifiable)? != exe_mount.id {
            return Err(ExecutableMappingUnverifiable);
        }
        let mappings = fs::read(proc.join("maps")).map_err(|_| ExecutableMappingUnverifiable)?;
        for line in mappings
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
        {
            if let Some(mapping) = Mapping::parse(line)? {
                mapping.verify(&root, &metadata, &mounts)?;
            }
        }
        check_basename(&path)?;

        let host_root = open_path(Path::new("/")).map_err(|_| AppIdentityUnproven)?;
        let subject = if path.starts_with("/snap") {
            snap_subject(&host_root, &path, exe_mount, &mounts.host)?
        } else {
            self.packages
                .lock()
                .map_err(|_| AppIdentityUnproven)?
                .subject(
                    &host_root,
                    &root,
                    &path,
                    &mut exe,
                    |file, key, algorithm| self.digest(file, key, algorithm),
                )?
                .map_or_else(
                    || {
                        self.digest(&mut exe, key, Algorithm::Sha256)
                            .map(|sum| format!("sha256:{sum}"))
                    },
                    Ok,
                )?
        };
        if subject
            .split_once(':')
            .is_some_and(|(_, name)| name.eq_ignore_ascii_case("alfonso"))
        {
            return Err(OperatorAppBlocked);
        }

        let current = fs::metadata(&exe_path).map_err(|_| StaleReference)?;
        if current.nlink() == 0 {
            return Err(ImageReplacedSinceLaunch);
        }
        if generation(pid)? != started
            || image_key(&current) != key
            || !same_file(
                &root.metadata().map_err(|_| StaleReference)?,
                &fs::metadata(&root_path).map_err(|_| StaleReference)?,
            )
            || mount_id(&root).map_err(|_| StaleReference)?
                != mount_id(&open_path(&root_path).map_err(|_| StaleReference)?)
                    .map_err(|_| StaleReference)?
            || !mounts.same_namespace(&proc)?
        {
            return Err(StaleReference);
        }
        Ok(VerifiedApp {
            generation: started,
            exe_device: key.dev,
            exe_inode: key.ino,
            path,
            subject,
        })
    }

    fn digest(
        &self,
        file: &mut File,
        key: ImageKey,
        algorithm: Algorithm,
    ) -> Result<String, Refusal> {
        let mut cache = self.digests.lock().map_err(|_| AppIdentityUnproven)?;
        if let Some(sum) = cache.values.get(&(key, algorithm)) {
            return Ok(sum.clone());
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| AppIdentityUnproven)?;
        let sum = match algorithm {
            Algorithm::Md5 => hash::<Md5>(file),
            Algorithm::Sha224 => hash::<Sha224>(file),
            Algorithm::Sha256 => hash::<Sha256>(file),
            Algorithm::Sha384 => hash::<Sha384>(file),
            Algorithm::Sha512 => hash::<Sha512>(file),
        }
        .map_err(|_| AppIdentityUnproven)?;
        if image_key(&file.metadata().map_err(|_| AppIdentityUnproven)?) != key {
            return Err(ImageReplacedSinceLaunch);
        }
        if cache.values.len() >= 4096 {
            cache.values.clear();
        }
        cache.values.insert((key, algorithm), sum.clone());
        #[cfg(test)]
        {
            cache.hashes += 1;
        }
        Ok(sum)
    }
}

fn generation(pid: u32) -> Result<ProcessGeneration, Refusal> {
    match process_generation(pid) {
        ProcessGenerationReading::Started {
            boot_id,
            start_ticks,
        } => Ok(ProcessGeneration {
            pid,
            boot_id,
            start_ticks,
        }),
        _ => Err(StaleReference),
    }
}

fn generation_evidence(generation: ProcessGeneration, exe_dev: u64, exe_ino: u64) -> String {
    use std::fmt::Write;
    let mut boot = String::with_capacity(32);
    for byte in generation.boot_id {
        let _ = write!(boot, "{byte:02x}");
    }
    format!("{boot}:{}:{exe_dev}:{exe_ino}", generation.start_ticks)
}

fn check_flatpak(proc: &Path, root: &Path) -> Result<(), Refusal> {
    let cgroup = fs::read(proc.join("cgroup")).map_err(|_| AppIdentityUnproven)?;
    if cgroup
        .split(|b| matches!(b, b'/' | b':'))
        .any(|part| part.starts_with(b"app-flatpak-"))
    {
        return Err(AppIdentityUnproven);
    }
    match fs::symlink_metadata(root.join(".flatpak-info")) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        _ => Err(AppIdentityUnproven),
    }
}

fn check_exe(path: &Path, metadata: &Metadata) -> Result<(), Refusal> {
    let raw = path.as_os_str().as_bytes();
    let anonymous = path.file_name().and_then(OsStr::to_str).and_then(|name| {
        name.strip_prefix('#')?
            .strip_suffix(" (deleted)")?
            .parse::<u64>()
            .ok()
    }) == Some(metadata.ino());
    if !metadata.is_file() || !path.is_absolute() || raw.starts_with(b"/memfd:") || anonymous {
        return Err(ExecutableMappingUnverifiable);
    }
    if metadata.nlink() == 0 {
        return Err(ImageReplacedSinceLaunch);
    }
    Ok(())
}

fn check_basename(path: &Path) -> Result<(), Refusal> {
    let basename = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or(AppIdentityUnproven)?;
    if matches!(basename, "xdg-dbus-proxy" | "bwrap") {
        return Err(AppIdentityUnproven);
    }
    let prefix = |prefixes: &[&str]| prefixes.iter().any(|p| basename.starts_with(p));
    if matches!(
        basename,
        "polkit-gnome-authentication-agent-1"
            | "polkit-kde-authentication-agent-1"
            | "polkit-mate-authentication-agent-1"
            | "lxpolkit"
            | "lxqt-policykit-agent"
            | "gcr-prompter"
            | "ksshaskpass"
            | "gnome-shell"
            | "plasmashell"
            | "kwin_x11"
            | "kwin_wayland"
    ) || basename.eq_ignore_ascii_case("alfonso")
        || prefix(&["xdg-desktop-portal", "pinentry", "ssh-askpass", "kwalletd"])
        || path
            .parent()
            .into_iter()
            .flat_map(Path::ancestors)
            .any(|dir| {
                dir.file_name()
                    .is_some_and(|name| name.as_bytes().starts_with(b"polkit"))
                    && (dir.starts_with("/usr/libexec") || dir.starts_with("/usr/lib"))
            })
    {
        return Err(OperatorAppBlocked);
    }
    if matches!(
        basename,
        "node"
            | "nodejs"
            | "java"
            | "sh"
            | "bash"
            | "dash"
            | "zsh"
            | "ld.so"
            | "mono"
            | "dotnet"
            | "qml"
            | "qmlscene"
            | "R"
            | "Rscript"
    ) || prefix(&[
        "python", "perl", "ruby", "gjs", "ld-linux", "electron", "lua", "tclsh", "wish", "php",
        "guile",
    ]) || path
        .strip_prefix("/usr/lib")
        .ok()
        .and_then(|p| p.components().next())
        .is_some_and(|c| c.as_os_str().as_bytes().starts_with(b"electron"))
    {
        return Err(InterpreterHostedImage);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Algorithm {
    Md5,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ImageKey {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

fn image_key(metadata: &Metadata) -> ImageKey {
    ImageKey {
        dev: metadata.dev(),
        ino: metadata.ino(),
        size: metadata.size(),
        mtime: (metadata.mtime(), metadata.mtime_nsec()),
        ctime: (metadata.ctime(), metadata.ctime_nsec()),
    }
}

#[derive(Debug, Default)]
struct DigestCache {
    values: HashMap<(ImageKey, Algorithm), String>,
    #[cfg(test)]
    hashes: usize,
}

fn hash<D: Digest + io::Write>(file: &mut File) -> io::Result<String>
where
    sha2::digest::Output<D>: std::fmt::LowerHex,
{
    let mut state = D::new();
    io::copy(file, &mut state)?;
    Ok(format!("{:x}", state.finalize()))
}

fn invalid() -> io::Error {
    io::ErrorKind::InvalidData.into()
}

fn same_file(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}

fn protected(meta: &Metadata) -> bool {
    meta.uid() == 0 && meta.mode() & 0o022 == 0
}

fn open_path(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH)
        .open(path)
}

fn fd_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

fn regular_read(file: &File) -> io::Result<File> {
    if !file.metadata()?.is_file() {
        return Err(invalid());
    }
    File::open(fd_path(file))
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn open_component(dir: &File, name: &OsStr) -> io::Result<File> {
    let name = CString::new(name.as_bytes())?;
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: 0x10 | 0x02,
    }; // RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS
       // SAFETY: Both syscall arguments point to initialized objects held across the call.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir.as_raw_fd(),
            name.as_ptr(),
            &how,
            size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Successful openat2 returned a fresh file descriptor.
    Ok(unsafe { File::from_raw_fd(fd as libc::c_int) })
}

fn link_contents(link: &File) -> io::Result<PathBuf> {
    let mut text = [0; 4096];
    // SAFETY: Empty path asks readlinkat to read the held O_PATH symlink; text is writable.
    let len = unsafe {
        libc::readlinkat(
            link.as_raw_fd(),
            c"".as_ptr(),
            text.as_mut_ptr().cast(),
            text.len(),
        )
    };
    if len < 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize == text.len() {
        return Err(invalid());
    }
    Ok(OsString::from_vec(text[..len as usize].to_vec()).into())
}

fn path_parts(path: &Path) -> VecDeque<OsString> {
    path.components()
        .map(|c| c.as_os_str().to_owned())
        .collect()
}

fn walk(root: &File, path: &Path, require_protected: bool) -> io::Result<File> {
    let root_meta = root.metadata()?;
    if !path.is_absolute() || !root_meta.is_dir() || (require_protected && !protected(&root_meta)) {
        return Err(invalid());
    }
    let mut parents = vec![root.try_clone()?];
    let mut parts = path_parts(path);
    let mut followed = 0;
    while let Some(part) = parts.pop_front() {
        match part.as_bytes() {
            b"/" => parents.truncate(1),
            b"." => (),
            b".." => {
                if parents.len() > 1 {
                    parents.pop();
                }
            }
            _ => {
                let leaf = open_component(parents.last().ok_or_else(invalid)?, &part)?;
                let meta = leaf.metadata()?;
                if meta.file_type().is_symlink() {
                    if followed == 40 || (require_protected && meta.uid() != 0) {
                        return Err(invalid());
                    }
                    followed += 1;
                    let mut target = path_parts(&link_contents(&leaf)?);
                    target.append(&mut parts);
                    parts = target;
                } else if require_protected && !protected(&meta) {
                    return Err(invalid());
                } else if parts.is_empty() {
                    return Ok(leaf);
                } else if meta.is_dir() {
                    parents.push(leaf);
                } else {
                    return Err(invalid());
                }
            }
        }
    }
    parents.pop().ok_or_else(invalid)
}

type Device = (u32, u32);

fn device(dev: u64) -> Device {
    (
        libc::major(dev as libc::dev_t),
        libc::minor(dev as libc::dev_t),
    )
}

fn parse_device(text: &[u8], radix: u32) -> Option<Device> {
    let (major, minor) = std::str::from_utf8(text).ok()?.split_once(':')?;
    Some((
        u32::from_str_radix(major, radix).ok()?,
        u32::from_str_radix(minor, radix).ok()?,
    ))
}

fn mount_id(file: &File) -> io::Result<u64> {
    // SAFETY: statx fills initialized storage, with the empty path naming the held fd.
    let mut stat: libc::statx = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::statx(
            file.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            libc::STATX_MNT_ID,
            &mut stat,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if stat.stx_mask & libc::STATX_MNT_ID == 0 {
        return Err(invalid());
    }
    Ok(stat.stx_mnt_id)
}

#[derive(Debug)]
struct Mapping<'a> {
    path: &'a [u8],
    dev: Device,
    ino: u64,
}

impl<'a> Mapping<'a> {
    fn parse(mut text: &'a [u8]) -> Result<Option<Self>, Refusal> {
        let mut token = || {
            text = text.trim_ascii_start();
            let end = text
                .iter()
                .position(|c| c.is_ascii_whitespace())
                .ok_or(ExecutableMappingUnverifiable)?;
            let value = &text[..end];
            text = &text[end..];
            Ok(value)
        };
        token()?; // address range
        if token()?.get(2) != Some(&b'x') {
            return Ok(None);
        }
        token()?; // file offset
        let dev = parse_device(token()?, 16).ok_or(ExecutableMappingUnverifiable)?;
        // The inode may be the last field when no pathname is printed.
        let text = text.trim_ascii_start();
        let end = text
            .iter()
            .position(|c| c.is_ascii_whitespace())
            .unwrap_or(text.len());
        let ino: u64 = std::str::from_utf8(&text[..end])
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or(ExecutableMappingUnverifiable)?;
        let path = text[end..].trim_ascii_start();
        if ino == 0 {
            return Ok(None);
        } // e.g. JIT pages, vDSO
        if path.starts_with(b"/memfd:") || !path.starts_with(b"/") {
            return Err(ExecutableMappingUnverifiable);
        }
        if path.ends_with(b" (deleted)") {
            return Err(ImageReplacedSinceLaunch);
        }
        // procfs escapes newlines but not literal backslashes. Neither spelling
        // can establish a unique pathname.
        if path.windows(4).any(|part| part == b"\\012") {
            return Err(ExecutableMappingUnverifiable);
        }
        Ok(Some(Self { path, dev, ino }))
    }

    fn verify(&self, root: &File, exe: &Metadata, mounts: &Mounts) -> Result<(), Refusal> {
        let path = Path::new(OsStr::from_bytes(self.path));
        // The maps device can be the btrfs superblock device. Only a real
        // fstat match (not the maps tuple) can exempt the executable itself.
        let is_exe = self.ino == exe.ino()
            && walk(root, path, false)
                .ok()
                .and_then(|leaf| leaf.metadata().ok())
                .is_some_and(|meta| same_file(exe, &meta));
        let leaf = walk(root, path, !is_exe).map_err(|_| ExecutableMappingUnverifiable)?;
        let meta = leaf.metadata().map_err(|_| ExecutableMappingUnverifiable)?;
        let mount = mounts.trusted_mount(&leaf)?;
        if !meta.is_file()
            || (is_exe && !same_file(exe, &meta))
            || meta.ino() != self.ino
            || (self.dev != device(meta.dev()) && self.dev != mount.dev)
        {
            return Err(ExecutableMappingUnverifiable);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Mount {
    id: u64,
    dev: Device,
    target: PathBuf,
    readonly: bool,
    fs_type: String,
    source: PathBuf,
}

impl Mount {
    fn read(path: &Path) -> io::Result<HashMap<u64, Self>> {
        let text = fs::read(path)?;
        text.split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| {
                Self::parse(line)
                    .map(|mount| (mount.id, mount))
                    .ok_or_else(invalid)
            })
            .collect()
    }

    fn parse(line: &[u8]) -> Option<Self> {
        let mut fields = line.split(|b| *b == b' ');
        let id = std::str::from_utf8(fields.next()?).ok()?.parse().ok()?;
        fields.next()?; // parent mount
        let dev = parse_device(fields.next()?, 10)?;
        fields.next()?; // root within the filesystem
        let target = mount_path(fields.next()?)?;
        let readonly = fields.next()?.split(|b| *b == b',').any(|opt| opt == b"ro");
        fields.find(|field| *field == b"-")?;
        let fs_type = std::str::from_utf8(fields.next()?).ok()?.to_owned();
        let source = mount_path(fields.next()?)?;
        Some(Self {
            id,
            dev,
            target,
            readonly,
            fs_type,
            source,
        })
    }

    fn trusted(&self) -> bool {
        if self.fs_type == "squashfs" && self.readonly && self.target.starts_with("/snap") {
            return true;
        }
        if self.fs_type.starts_with("fuse")
            || matches!(
                self.fs_type.as_str(),
                "tmpfs" | "overlay" | "overlayfs" | "zfs" | "nfs" | "nfs4" | "virtiofs" | "9p"
            )
        {
            return false;
        }
        if !self.source.starts_with("/dev")
            || self
                .source
                .components()
                .any(|part| part == Component::ParentDir)
        {
            return false;
        }
        if fs::metadata(&self.source).is_ok_and(|meta| meta.file_type().is_block_device()) {
            return true;
        }
        // Some boot configurations put /dev/root in mountinfo without a
        // node of that name. Resolve that alias using the kernel's devtmpfs name.
        if self.source != Path::new("/dev/root") {
            return false;
        }
        let (major, minor) = self.dev;
        let Ok(uevent) = fs::read_to_string(format!("/sys/dev/block/{major}:{minor}/uevent"))
        else {
            return false;
        };
        let Some(name) = uevent
            .lines()
            .find_map(|line| line.strip_prefix("DEVNAME="))
        else {
            return false;
        };
        let path = Path::new(name);
        if path.is_absolute()
            || path
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return false;
        }
        fs::metadata(Path::new("/dev").join(path))
            .is_ok_and(|meta| meta.file_type().is_block_device() && device(meta.rdev()) == self.dev)
    }
}

fn mount_path(raw: &[u8]) -> Option<PathBuf> {
    let mut path = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'\\' {
            let value = match raw.get(i + 1..i + 4)? {
                b"040" => b' ',
                b"011" => b'\t',
                b"012" => b'\n',
                b"134" => b'\\',
                _ => return None,
            };
            path.push(value);
            i += 4;
        } else {
            path.push(raw[i]);
            i += 1;
        }
    }
    Some(OsString::from_vec(path).into())
}

struct Mounts {
    namespace: File,
    host: HashMap<u64, Mount>,
    private: HashMap<u64, Mount>,
}

impl Mounts {
    fn read(proc: &Path) -> Result<Self, Refusal> {
        let namespace =
            File::open(proc.join("ns/mnt")).map_err(|_| ExecutableMappingUnverifiable)?;
        let host = Mount::read(Path::new("/proc/self/mountinfo"))
            .map_err(|_| ExecutableMappingUnverifiable)?;
        let private = if owned_mount_namespace(&namespace).unwrap_or(false) {
            Mount::read(&proc.join("mountinfo")).map_err(|_| ExecutableMappingUnverifiable)?
        } else {
            HashMap::new()
        };
        Ok(Self {
            namespace,
            host,
            private,
        })
    }

    fn trusted_mount(&self, file: &File) -> Result<&Mount, Refusal> {
        let id = mount_id(file).map_err(|_| ExecutableMappingUnverifiable)?;
        self.record(id)
            .filter(|mount| mount.trusted())
            .ok_or(ExecutableMappingUnverifiable)
    }

    fn record(&self, id: u64) -> Option<&Mount> {
        self.host.get(&id).or_else(|| self.private.get(&id))
    }

    fn same_namespace(&self, proc: &Path) -> Result<bool, Refusal> {
        let ns = self.namespace.metadata().map_err(|_| StaleReference)?;
        let current = fs::metadata(proc.join("ns/mnt")).map_err(|_| StaleReference)?;
        Ok(same_file(&ns, &current))
    }
}

fn owned_mount_namespace(namespace: &File) -> io::Result<bool> {
    const NS_GET_USERNS: libc::c_ulong = 0xb701;
    // SAFETY: This ioctl takes no pointer argument and returns a fresh namespace fd.
    let fd = unsafe { libc::ioctl(namespace.as_raw_fd(), NS_GET_USERNS as _) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: A successful NS_GET_USERNS transfers ownership of the returned fd.
    let owner = unsafe { File::from_raw_fd(fd) }.metadata()?;
    Ok(same_file(&owner, &fs::metadata("/proc/self/ns/user")?))
}

fn snap_subject(
    root: &File,
    path: &Path,
    mount: &Mount,
    host: &HashMap<u64, Mount>,
) -> Result<String, Refusal> {
    let mut parts = path
        .strip_prefix("/snap")
        .map_err(|_| AppIdentityUnproven)?
        .components();
    let (
        Some(Component::Normal(name)),
        Some(Component::Normal(revision)),
        Some(Component::Normal(_)),
    ) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(AppIdentityUnproven);
    };
    let name = name.to_str().ok_or(AppIdentityUnproven)?;
    let snap = Path::new("/snap").join(name);
    let revision_path = snap.join(revision);
    if !mount.readonly || mount.fs_type != "squashfs" || !mount.target.starts_with("/snap") {
        return Err(AppIdentityUnproven);
    }
    let directory = walk(root, &snap, true).map_err(|_| AppIdentityUnproven)?;
    let current =
        open_component(&directory, OsStr::new("current")).map_err(|_| ImageReplacedSinceLaunch)?;
    let meta = current.metadata().map_err(|_| AppIdentityUnproven)?;
    if !meta.file_type().is_symlink() || meta.uid() != 0 {
        return Err(AppIdentityUnproven);
    }
    if link_contents(&current).map_err(|_| AppIdentityUnproven)? != Path::new(revision)
        || !host.values().any(|host| {
            host.target == revision_path
                && host.dev == mount.dev
                && host.readonly
                && host.fs_type == "squashfs"
        })
    {
        return Err(ImageReplacedSinceLaunch);
    }
    Ok(format!("snap:{name}"))
}
