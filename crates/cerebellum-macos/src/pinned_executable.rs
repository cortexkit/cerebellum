//! Cursor helpers run only the executable captured when the module started.
//! The module launches its helper from the installed path while that path
//! still names the startup inode; the desk probe pins a private hard link.

#[cfg(any(test, feature = "desk-probe"))]
use std::fs::DirBuilder;
use std::fs::{self, File};
use std::io;
#[cfg(any(test, feature = "desk-probe"))]
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Inode {
    device: u64,
    number: u64,
}

impl Inode {
    fn of(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::other("helper image is not a regular file"));
        }
        Ok(Self {
            device: metadata.dev(),
            number: metadata.ino(),
        })
    }
}

/// Owns the startup image and, when linking succeeds, its private launch path.
/// Dropping it removes the link, including on an early startup failure.
pub struct PinnedExecutable {
    // Keeping the file open also prevents inode reuse if its last path is lost.
    _image: File,
    startup_inode: Inode,
    pin: Option<PathBuf>,
    directory: Option<PathBuf>,
    #[cfg(target_os = "macos")]
    fallback_identity: Option<crate::ExecutedImageIdentity>,
}

impl PinnedExecutable {
    /// Capture the kernel's executable path before configuration or serving can
    /// start a helper. If the module's startup executable cannot be read, its
    /// helper cannot be launched.
    #[cfg(target_os = "macos")]
    pub fn at_startup() -> io::Result<Self> {
        let pid = std::process::id();
        let source = crate::process_executable_path(pid)
            .ok()
            .flatten()
            .ok_or_else(|| io::Error::other("startup executable path is unreadable"))?;
        let image = File::open(&source)?;
        let startup_inode = Inode::of(&image)?;
        let mut result = Self::capture(image, startup_inode);
        // The module never launches its helper from a linked copy. macOS
        // privacy permissions such as Screen Recording follow the executable's
        // path for a tool outside an app bundle, so a copy at another path is a
        // new app to the person and prompts again. The helper starts from the
        // installed path instead, only while that path still names the startup
        // inode and the child's code identity matches the running module's.
        result.fallback_identity = crate::executed_image_identity(pid).ok();
        Ok(result)
    }

    /// The desk probe embeds the module library but uses the sibling module
    /// binary as its helper. Require a pin: that binary cannot use the probe's
    /// running code-signing identity to validate an unpinned fallback.
    #[cfg(all(target_os = "macos", feature = "desk-probe"))]
    pub fn for_probe(source: &Path) -> io::Result<Self> {
        let image = File::open(source)?;
        let inode = Inode::of(&image)?;
        let mut result = Self::capture(image, inode);
        let pid = std::process::id();
        let crate::ProcessStartTime::Started(start) = crate::process_start_time(pid) else {
            return Err(io::Error::other("probe start time is unreadable"));
        };
        let home = std::env::var_os("HOME").map(PathBuf::from);
        result.pin_with_fallback(source, home.as_deref(), &std::env::temp_dir(), pid, start)?;
        Ok(result)
    }

    fn capture(image: File, startup_inode: Inode) -> Self {
        Self {
            _image: image,
            startup_inode,
            pin: None,
            directory: None,
            #[cfg(target_os = "macos")]
            fallback_identity: None,
        }
    }

    // Only the desk probe pins a copy now; see `at_startup`.
    #[cfg(any(test, feature = "desk-probe"))]
    fn pin_with_fallback(
        &mut self,
        source: &Path,
        home: Option<&Path>,
        temporary: &Path,
        pid: u32,
        start: u64,
    ) -> io::Result<()> {
        // Unlike the per-user temp folder, Caches is not periodically purged
        // while a long-running module may still need its startup image.
        if let Some(home) = home.filter(|home| home.is_absolute()) {
            let root = home.join("Library/Caches/ck-cerebellum/helper-pins");
            if self.pin_in(source, &root, pid, start).is_ok() {
                return Ok(());
            }
            // A failed link can leave a per-start directory behind. Remove it
            // before the temp attempt takes ownership of a different directory.
            if let Some(directory) = self.directory.take() {
                remove_pin(&directory);
            }
        }
        self.pin_in(
            source,
            &temporary.join("ck-cerebellum-helper-pins"),
            pid,
            start,
        )
    }

    #[cfg(any(test, feature = "desk-probe"))]
    fn pin_in(&mut self, source: &Path, root: &Path, pid: u32, start: u64) -> io::Result<()> {
        if let Some(parent) = root.parent() {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }
        private_directory(root)?;
        sweep_stale(root, |pid, start| {
            #[cfg(target_os = "macos")]
            {
                match crate::process_start_time(pid) {
                    crate::ProcessStartTime::NoSuchProcess => false,
                    crate::ProcessStartTime::Started(actual) => actual == start,
                    // Lack of evidence is not permission to unlink a live pin.
                    _ => true,
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = (pid, start);
                true
            }
        })?;
        let directory = root.join(format!("{pid}-{start}"));
        DirBuilder::new().mode(0o700).create(&directory)?;
        self.directory = Some(directory.clone());
        let pin = directory.join("module");
        fs::hard_link(source, &pin)?;
        // The source path can be replaced between open and link. Compare the
        // link to the open startup file, not to a second stat of the source.
        if Inode::of(&File::open(&pin)?)? != self.startup_inode {
            return Err(io::Error::other(
                "startup executable changed before linking",
            ));
        }
        self.pin = Some(pin);
        Ok(())
    }

    /// Select the private link, or the ordinary path only while it still names
    /// the startup inode. This check is repeated for every helper restart.
    pub fn launch_path(&self) -> io::Result<PathBuf> {
        match &self.pin {
            Some(pin) => self.path_for(pin),
            None => self.path_for(&std::env::current_exe()?),
        }
    }

    fn path_for(&self, current_exe: &Path) -> io::Result<PathBuf> {
        let path = self.pin.as_deref().unwrap_or(current_exe);
        if Inode::of(&File::open(path)?)? != self.startup_inode {
            return Err(io::Error::other(
                "helper executable no longer matches startup",
            ));
        }
        Ok(path.to_owned())
    }

    /// An updater can replace a fallback path after the inode check. Before
    /// releasing the suspended child, require the code-signing identity captured
    /// from the running module. Replacing the original path cannot redirect a
    /// launch through the private hard link.
    #[cfg(target_os = "macos")]
    pub fn accepts_child(&self, pid: u32) -> bool {
        self.pin.is_some()
            || self.fallback_identity.as_ref().is_some_and(|startup| {
                crate::executed_image_identity(pid).as_ref().ok() == Some(startup)
            })
    }
}

impl Drop for PinnedExecutable {
    fn drop(&mut self) {
        if let Some(directory) = &self.directory {
            remove_pin(directory);
        }
    }
}

#[cfg(any(test, feature = "desk-probe"))]
fn private_directory(path: &Path) -> io::Result<()> {
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path)?;
            // SAFETY: geteuid takes no arguments and has no failure case.
            let owner = unsafe { geteuid() };
            if metadata.is_dir() && metadata.mode() & 0o777 == 0o700 && metadata.uid() == owner {
                Ok(())
            } else {
                Err(io::Error::other("helper pin directory is not private"))
            }
        }
        Err(error) => Err(error),
    }
}

#[cfg(any(test, feature = "desk-probe"))]
extern "C" {
    fn geteuid() -> u32;
}

fn remove_pin(directory: &Path) {
    // Never follow a substituted directory symlink during cleanup.
    if fs::symlink_metadata(directory).is_ok_and(|metadata| metadata.is_dir()) {
        let _ = fs::remove_file(directory.join("module"));
        let _ = fs::remove_dir(directory);
    }
}

#[cfg(any(test, feature = "desk-probe"))]
fn sweep_stale(root: &Path, mut is_live: impl FnMut(u32, u64) -> bool) -> io::Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some((pid, start)) = name.to_str().and_then(|name| name.split_once('-')) else {
            continue;
        };
        let (Ok(pid), Ok(start)) = (pid.parse(), start.parse()) else {
            continue;
        };
        if !is_live(pid, start) {
            remove_pin(&entry.path());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    const CHILD: &str = "pinned_executable::tests::helper_fixture_reports_its_inode";
    const OUTPUT: &str = "CEREBELLUM_PINNED_EXECUTABLE_TEST_OUTPUT";

    struct Fixture {
        directory: PathBuf,
        module: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            // Tests that launch a copy of their own binary use /tmp rather
            // than the operator's TMPDIR.
            let directory = PathBuf::from("/tmp").join(format!(
                "ck-helper-pin-test-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            DirBuilder::new().mode(0o700).create(&directory).unwrap();
            let module = directory.join("module");
            fs::copy(std::env::current_exe().unwrap(), &module).unwrap();
            Self { directory, module }
        }

        fn capture(&self) -> PinnedExecutable {
            let image = File::open(&self.module).unwrap();
            let inode = Inode::of(&image).unwrap();
            PinnedExecutable::capture(image, inode)
        }

        fn pin(&self) -> PinnedExecutable {
            let mut pin = self.capture();
            pin.pin_with_fallback(
                &self.module,
                Some(&self.directory.join("home")),
                &self.directory.join("temporary"),
                42,
                100,
            )
            .unwrap();
            pin
        }

        fn replace_module(&self) {
            let replacement = self.directory.join("replacement");
            fs::copy(std::env::current_exe().unwrap(), &replacement).unwrap();
            fs::rename(replacement, &self.module).unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.directory).unwrap();
        }
    }

    #[test]
    fn helper_fixture_reports_its_inode() {
        let Some(output) = std::env::var_os(OUTPUT) else {
            return;
        };
        let inode = Inode::of(&File::open(std::env::current_exe().unwrap()).unwrap()).unwrap();
        fs::write(output, format!("{}:{}", inode.device, inode.number)).unwrap();
    }

    #[test]
    fn helper_launch_keeps_startup_inode_after_original_path_is_replaced() {
        let fixture = Fixture::new();
        let pin = fixture.pin();
        let startup_inode = Inode::of(&File::open(&fixture.module).unwrap()).unwrap();
        fixture.replace_module();
        assert_ne!(
            Inode::of(&File::open(&fixture.module).unwrap()).unwrap(),
            startup_inode,
            "the installer must really replace the inode, not overwrite its bytes"
        );
        let launch = pin.path_for(&fixture.module).unwrap();
        let output = fixture.directory.join("child-inode");
        let status = Command::new(&launch)
            .args(["--exact", CHILD, "--nocapture"])
            .env(OUTPUT, &output)
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(
            fs::read_to_string(output).unwrap(),
            format!("{}:{}", startup_inode.device, startup_inode.number),
            "the helper must execute the startup inode, not the replacement"
        );
        // A crash/restart must select the same link as the first launch.
        assert_eq!(pin.path_for(&fixture.module).unwrap(), launch);
        assert_eq!(pin.launch_path().unwrap(), launch);
        fs::remove_file(&fixture.module).unwrap();
        assert_eq!(pin.launch_path().unwrap(), launch);
    }

    #[test]
    fn pin_uses_private_cache_root_instead_of_temporary_root() {
        let fixture = Fixture::new();
        let pin = fixture.pin();
        let root = fixture
            .directory
            .join("home/Library/Caches/ck-cerebellum/helper-pins");
        let launch = root.join("42-100/module");
        assert_eq!(pin.launch_path().unwrap(), launch);
        assert_eq!(fs::metadata(&root).unwrap().mode() & 0o777, 0o700);
        assert!(!fixture.directory.join("temporary").exists());
        drop(pin);
        assert!(!launch.exists());
        assert!(!root.join("42-100").exists());
    }

    #[test]
    fn unavailable_cache_directory_falls_back_to_private_temporary_pin() {
        let fixture = Fixture::new();
        let home = fixture.directory.join("home");
        fs::create_dir(&home).unwrap();
        fs::write(home.join("Library"), b"not a directory").unwrap();
        let pin = fixture.pin();
        let root = fixture
            .directory
            .join("temporary/ck-cerebellum-helper-pins");
        let launch = root.join("42-100/module");
        assert_eq!(pin.launch_path().unwrap(), launch);
        assert_eq!(fs::metadata(&root).unwrap().mode() & 0o777, 0o700);
        fixture.replace_module();
        assert_eq!(pin.launch_path().unwrap(), launch);
        drop(pin);
        assert!(!root.join("42-100").exists());
    }

    #[test]
    fn failed_pinning_falls_back_only_while_startup_inode_matches() {
        let fixture = Fixture::new();
        let mut pin = fixture.capture();
        let blocked_root = fixture.directory.join("not-a-directory");
        fs::write(&blocked_root, b"occupied").unwrap();
        assert!(pin.pin_in(&fixture.module, &blocked_root, 42, 100).is_err());
        assert_eq!(pin.path_for(&fixture.module).unwrap(), fixture.module);
        fixture.replace_module();
        assert!(pin.path_for(&fixture.module).is_err());
    }

    #[test]
    fn replacement_between_open_and_link_is_refused() {
        let fixture = Fixture::new();
        let mut pin = fixture.capture();
        fixture.replace_module();
        assert!(pin
            .pin_with_fallback(
                &fixture.module,
                Some(&fixture.directory.join("home")),
                &fixture.directory.join("temporary"),
                42,
                100,
            )
            .is_err());
        assert!(pin.pin.is_none());
        assert!(pin.path_for(&fixture.module).is_err());
        assert!(!fixture
            .directory
            .join("home/Library/Caches/ck-cerebellum/helper-pins/42-100")
            .exists());
        let directory = pin.directory.clone().unwrap();
        assert_eq!(
            directory,
            fixture
                .directory
                .join("temporary/ck-cerebellum-helper-pins/42-100")
        );
        drop(pin);
        assert!(!directory.exists());
    }

    #[test]
    fn private_pin_is_removed_on_clean_shutdown() {
        let fixture = Fixture::new();
        let pin = fixture.pin();
        let directory = pin.directory.clone().unwrap();
        assert_eq!(fs::metadata(&directory).unwrap().mode() & 0o777, 0o700);
        assert_eq!(
            fs::metadata(directory.parent().unwrap()).unwrap().mode() & 0o777,
            0o700
        );
        drop(pin);
        assert!(!directory.exists());
    }

    #[test]
    fn stale_sweep_preserves_live_generations_and_ignores_symlinks() {
        let fixture = Fixture::new();
        let root = fixture.directory.join("pins");
        private_directory(&root).unwrap();
        for name in ["41-100", "42-100", "42-99"] {
            let directory = root.join(name);
            private_directory(&directory).unwrap();
            fs::write(directory.join("module"), b"old pin").unwrap();
        }
        std::os::unix::fs::symlink(&fixture.directory, root.join("43-100")).unwrap();
        sweep_stale(&root, |pid, start| pid == 42 && start == 100).unwrap();
        assert!(!root.join("41-100").exists());
        assert!(!root.join("42-99").exists());
        assert!(root.join("42-100/module").exists());
        assert!(fixture.module.exists(), "cleanup must not follow symlinks");
        assert!(private_directory(&root.join("43-100")).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn fallback_validates_the_suspended_child_before_release() {
        let fixture = Fixture::new();
        let mut pin = fixture.capture();
        pin.fallback_identity = crate::executed_image_identity(std::process::id()).ok();
        assert!(pin.fallback_identity.is_some());
        let (same, _pipe) = crate::spawn_barred_stdin(
            &pin.path_for(&fixture.module).unwrap(),
            &["--exact".into(), CHILD.into()],
        )
        .unwrap();
        assert!(pin.accepts_child(same.generation().pid));
        drop(same);
        // Simulate a path replacement after the fallback inode check. The
        // suspended wrong image must never be released to run its first line.
        let (different, _pipe) =
            crate::spawn_barred_stdin(Path::new("/usr/bin/true"), &[]).unwrap();
        assert!(!pin.accepts_child(different.generation().pid));
    }
}
