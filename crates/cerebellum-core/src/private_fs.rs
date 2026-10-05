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

#[cfg(not(unix))]
pub fn create_dir_all(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)
}

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

#[cfg(not(unix))]
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

#[cfg(not(unix))]
pub fn tighten_data_tree(_root: &Path) -> usize {
    0
}

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
