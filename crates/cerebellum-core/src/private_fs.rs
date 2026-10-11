//! Owner-only filesystem primitives for durable private state.
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::Path;

#[cfg(unix)]
pub fn create_dir_all(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        current.push(component);
        if current.exists() {
            if current.is_dir() {
                continue;
            }
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "an existing path component is not a directory",
            ));
        }
        match fs::DirBuilder::new().mode(0o700).create(&current) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists && current.is_dir() => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(windows)]
pub fn create_dir_all(path: &Path) -> io::Result<()> {
    reject_reparse_components(path)?;
    cortexkit_lease::create_private_dir(path)
}

#[cfg(not(any(unix, windows)))]
pub fn create_dir_all(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)
}

#[cfg(not(windows))]
pub fn create_new_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

#[cfg(not(windows))]
pub fn open_append(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

#[cfg(not(windows))]
pub fn open_lock(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

#[cfg(unix)]
pub fn create_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(windows)]
pub fn create_dir(path: &Path) -> io::Result<()> {
    // Unlike the recursive commons helper, this primitive requires a missing
    // leaf and an existing parent, matching std::fs::create_dir.
    match fs::symlink_metadata(path) {
        Ok(_) => return Err(io::ErrorKind::AlreadyExists.into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !fs::symlink_metadata(parent)?.is_dir() {
        return Err(io::ErrorKind::NotADirectory.into());
    }
    reject_reparse_components(path)?;
    cortexkit_lease::create_private_dir(path)
}

#[cfg(not(any(unix, windows)))]
pub fn create_dir(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new().create(path)
}

#[cfg(unix)]
pub fn tighten_data_tree(root: &Path) -> usize {
    use std::os::unix::fs::PermissionsExt;
    let mut failures = 0;
    match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.file_type().is_symlink() => return 0,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return 0,
        Err(_) => return 1,
        Ok(metadata) if !metadata.is_dir() => return 0,
        Ok(_) => {}
    }
    let mut directories = vec![root.to_path_buf()];
    for relative in ["journal", "browser", "browser/profiles"] {
        directories.push(root.join(relative));
    }
    for directory in directories {
        let mut ancestor = directory.parent();
        let mut unsafe_parent = false;
        while let Some(parent) = ancestor {
            if parent == root.parent().unwrap_or(root) {
                break;
            }
            if fs::symlink_metadata(parent)
                .map(|metadata| metadata.file_type().is_symlink())
                .unwrap_or(false)
            {
                unsafe_parent = true;
                break;
            }
            ancestor = parent.parent();
        }
        if unsafe_parent {
            continue;
        }
        match fs::symlink_metadata(&directory) {
            Ok(meta) if meta.file_type().is_symlink() => continue,
            Ok(meta) if meta.is_dir() => {
                if meta.permissions().mode() & 0o777 != 0o700
                    && fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).is_err()
                {
                    failures += 1;
                }
            }
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => {
                failures += 1;
                continue;
            }
        }
        if directory == root.join("journal") || directory == root.join("browser") {
            match fs::read_dir(&directory) {
                Ok(entries) => {
                    for entry in entries {
                        let Ok(entry) = entry else {
                            failures += 1;
                            continue;
                        };
                        let path = entry.path();
                        match fs::symlink_metadata(&path) {
                            Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => {}
                            Ok(meta) if meta.permissions().mode() & 0o777 != 0o600 => {
                                if fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                                    .is_err()
                                {
                                    failures += 1;
                                }
                            }
                            Ok(_) => {}
                            Err(_) => failures += 1,
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(_) => failures += 1,
            }
        }
    }
    failures
}

#[cfg(not(any(unix, windows)))]
pub fn tighten_data_tree(_root: &Path) -> usize {
    0
}

#[cfg(not(windows))]
pub fn create_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

#[cfg(windows)]
fn open_private(path: &Path, mut options: OpenOptions) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    // Refuse existing reparse points before opening or truncating. Opening the
    // leaf itself also prevents a raced-in reparse point from being followed.
    reject_reparse_components(path)?;
    cortexkit_lease::protect_file(path)?;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path)?;
    cortexkit_lease::protect_file(path)?;
    Ok(file)
}

#[cfg(windows)]
pub fn create_new_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    open_private(path, options)
}

#[cfg(windows)]
pub fn open_append(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    open_private(path, options)
}

#[cfg(windows)]
pub fn open_lock(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    open_private(path, options)
}

#[cfg(windows)]
pub fn create_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    open_private(path, options)
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(windows)]
fn reject_reparse_components(path: &Path) -> io::Result<()> {
    // Commons opens the leaf without following it; check existing ancestors
    // too so a directory junction does not redirect private state elsewhere.
    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        current.push(component);
        if matches!(component, std::path::Component::Prefix(_)) {
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if is_reparse_point(&metadata) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "a private path component is a reparse point",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(windows)]
pub fn tighten_data_tree(root: &Path) -> usize {
    let mut failures = 0;
    match fs::symlink_metadata(root) {
        Ok(metadata) if is_reparse_point(&metadata) || !metadata.is_dir() => return 0,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return 0,
        Err(_) => return 1,
        Ok(_) => {}
    }
    if reject_reparse_components(root).is_err() {
        return 1;
    }
    // Visit only module-owned directories and immediate journal/browser files.
    // Chrome files are not visited; Windows can still propagate directory ACLs
    // to unprotected descendants, while protected child ACLs remain unchanged.
    for directory in [
        root.to_path_buf(),
        root.join("journal"),
        root.join("browser"),
        root.join("browser/profiles"),
    ] {
        let mut ancestor = directory.parent();
        let mut unsafe_parent = false;
        while let Some(parent) = ancestor {
            if parent == root.parent().unwrap_or(root) {
                break;
            }
            if fs::symlink_metadata(parent)
                .map(|metadata| is_reparse_point(&metadata))
                .unwrap_or(false)
            {
                unsafe_parent = true;
                break;
            }
            ancestor = parent.parent();
        }
        if unsafe_parent {
            continue;
        }
        match fs::symlink_metadata(&directory) {
            Ok(meta) if is_reparse_point(&meta) || !meta.is_dir() => continue,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => {
                failures += 1;
                continue;
            }
            Ok(_) => {}
        }
        if cortexkit_lease::create_private_dir(&directory).is_err() {
            failures += 1;
        }
        if directory == root.join("journal") || directory == root.join("browser") {
            match fs::read_dir(&directory) {
                Ok(entries) => {
                    for entry in entries {
                        let Ok(entry) = entry else {
                            failures += 1;
                            continue;
                        };
                        let path = entry.path();
                        match fs::symlink_metadata(&path) {
                            Ok(meta) if is_reparse_point(&meta) || !meta.is_file() => {}
                            Ok(_) => {
                                if cortexkit_lease::protect_file(&path).is_err() {
                                    failures += 1;
                                }
                            }
                            Err(_) => failures += 1,
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(_) => failures += 1,
            }
        }
    }
    failures
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn private_creation_uses_owner_only_modes() {
        let scratch = std::env::temp_dir().join(format!("private-fs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&scratch);
        let nested = scratch.join("journal");
        create_dir_all(&nested).unwrap();
        assert_eq!(
            fs::metadata(&scratch).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&nested).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let file_path = nested.join("state.json");
        drop(create_new_file(&file_path).unwrap());
        assert_eq!(
            fs::metadata(file_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(scratch).unwrap();
    }

    #[test]
    fn tightening_skips_symlinks_and_chrome_profile_contents() {
        let scratch = std::env::temp_dir().join(format!("private-tighten-{}", std::process::id()));
        let _ = fs::remove_dir_all(&scratch);
        let journal = scratch.join("journal");
        let browser = scratch.join("browser");
        let profiles = browser.join("profiles");
        fs::create_dir_all(&profiles).unwrap();
        fs::create_dir_all(&journal).unwrap();
        let owned = journal.join("state.json");
        let chrome = profiles.join("Cookies");
        fs::write(&owned, b"owned").unwrap();
        fs::write(&chrome, b"chrome").unwrap();
        for path in [&scratch, &journal, &browser, &profiles] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::set_permissions(&owned, fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(&chrome, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(tighten_data_tree(&scratch), 0);
        for path in [&scratch, &journal, &browser, &profiles] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        assert_eq!(
            fs::metadata(&owned).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(chrome).unwrap().permissions().mode() & 0o777,
            0o644
        );
        fs::remove_dir_all(scratch).unwrap();
    }

    #[test]
    fn tightening_does_not_follow_directory_symlinks() {
        use std::os::unix::fs::symlink;
        let scratch = std::env::temp_dir().join(format!("private-symlink-{}", std::process::id()));
        let target =
            std::env::temp_dir().join(format!("private-symlink-target-{}", std::process::id()));
        let _ = fs::remove_dir_all(&scratch);
        let _ = fs::remove_dir_all(&target);
        fs::create_dir_all(&scratch).unwrap();
        fs::create_dir_all(target.join("profiles")).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(target.join("profiles"), fs::Permissions::from_mode(0o755)).unwrap();
        symlink(&target, scratch.join("browser")).unwrap();
        assert_eq!(tighten_data_tree(&scratch), 0);
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(
            fs::metadata(target.join("profiles"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        fs::remove_dir_all(scratch).unwrap();
        fs::remove_dir_all(target).unwrap();
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use cortexkit_lease::test_support::{
        assert_broad_inherited, assert_owner_only, grant_everyone, read_acl,
    };
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Scratch(PathBuf);

    impl Scratch {
        fn broad(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("private-fs-{label}-{}-{nonce}", std::process::id()));
            fs::create_dir(&path).unwrap();
            // Set a known broad parent ACL independently of the writer under test.
            // A private temp directory must not make a missing hardening step pass.
            grant_everyone(&path);
            let control = path.join("inherited-control");
            fs::write(&control, b"control").unwrap();
            assert_broad_inherited(&control);
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn assert_protected_owner_only(path: &Path, directory: bool) {
        assert_owner_only(path, directory, true);
        let acl = read_acl(path);
        const INHERITED_ACE: u8 = 0x10;
        for ace in &acl.aces {
            assert_eq!(
                ace.flags & INHERITED_ACE,
                0,
                "no inherited entries: {path:?}"
            );
        }
        if !directory {
            assert_eq!(acl.aces[0].flags, 0, "file ACE has no inheritance flags");
        }
    }

    #[test]
    fn windows_files_have_protected_owner_only_dacls() {
        let scratch = Scratch::broad("files");
        let openers = [
            ("new", create_new_file as fn(&Path) -> io::Result<File>),
            ("append", open_append),
            ("lock", open_lock),
            ("truncate", create_file),
        ];
        for (label, open) in openers {
            let path = scratch.0.join(label);
            drop(open(&path).unwrap());
            assert_protected_owner_only(&path, false);
        }
        for (label, open) in &openers[1..] {
            let path = scratch.0.join(format!("existing-{label}"));
            fs::write(&path, b"old state").unwrap();
            assert_broad_inherited(&path);
            drop(open(&path).unwrap());
            assert_protected_owner_only(&path, false);
        }
    }

    #[test]
    fn windows_directories_have_protected_owner_only_dacls() {
        let scratch = Scratch::broad("directories");
        let parent = scratch.0.join("journal");
        let nested = parent.join("nested");
        create_dir_all(&nested).unwrap();
        for path in [&parent, &nested] {
            assert_protected_owner_only(path, true);
        }
        let single = scratch.0.join("single");
        create_dir(&single).unwrap();
        assert_protected_owner_only(&single, true);
        assert_eq!(
            create_dir(&single).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            create_dir(&scratch.0.join("missing/leaf"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        let existing = scratch.0.join("existing");
        fs::create_dir(&existing).unwrap();
        assert_broad_inherited(&existing);
        create_dir_all(&existing).unwrap();
        assert_protected_owner_only(&existing, true);
    }

    #[test]
    fn windows_tightening_preserves_protected_chrome_file_dacls() {
        let scratch = Scratch::broad("tighten");
        let journal = scratch.0.join("journal");
        let browser = scratch.0.join("browser");
        let profiles = browser.join("profiles");
        fs::create_dir_all(&profiles).unwrap();
        fs::create_dir(&journal).unwrap();
        let state = journal.join("state.json");
        let catalog = browser.join("catalog.json");
        let chrome = profiles.join("Cookies");
        for path in [&state, &catalog, &chrome] {
            fs::write(path, b"fixture").unwrap();
            assert_broad_inherited(path);
        }
        // A protected Chrome ACL is outside module ownership. Windows may
        // propagate directory ACLs to unprotected children, but not this file.
        grant_everyone(&chrome);
        let chrome_before = read_acl(&chrome);
        assert_eq!(tighten_data_tree(&scratch.0), 0);
        for path in [&scratch.0, &journal, &browser, &profiles] {
            assert_protected_owner_only(path, true);
        }
        for path in [&state, &catalog] {
            assert_protected_owner_only(path, false);
        }
        assert_eq!(read_acl(&chrome), chrome_before);
    }
}
