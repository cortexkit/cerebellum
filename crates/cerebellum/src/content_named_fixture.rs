use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// Keep fixture paths stable across test runs so macOS does not reassess a new
/// executable on every run. `/tmp` is intentional: codesign can hang during
/// system-policy evaluation of files under the per-user `$TMPDIR` on macOS 27.
/// Old content versions are pruned only when they are older than a day and
/// outside the three newest siblings, protecting concurrent test executables.
pub(crate) fn content_named_fixture(
    label: &str,
    file_name: &str,
    bytes: &[u8],
    mode: u32,
) -> PathBuf {
    assert!(
        !label.is_empty()
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
        "fixture label must be a simple path component"
    );
    assert!(
        !file_name.is_empty()
            && file_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
        "fixture file name must be a simple path component"
    );
    let digest = format!("{:x}", Sha256::digest(bytes));
    let directory = Path::new("/tmp").join(format!("cerebellum-fixture-{label}-{digest}"));
    fs::create_dir_all(&directory).expect("create content-named fixture directory");
    let path = directory.join(file_name);
    if matches_fixture(&path, bytes, mode) {
        return path;
    }

    // A unique sibling plus rename prevents concurrent readers from seeing a
    // partial script, including when an older fixture needs repair.
    let temp = loop {
        let candidate = directory.join(format!(
            ".{file_name}-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => break (candidate, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("create fixture temp file: {error}"),
        }
    };
    let (temporary_path, mut file) = temp;
    let write_result = (|| -> std::io::Result<()> {
        file.write_all(bytes)?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        drop(file);
        fs::rename(&temporary_path, &path)?;
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary_path);
        panic!("write content-named fixture: {error}");
    }
    assert!(
        matches_fixture(&path, bytes, mode),
        "fixture content or mode changed after write"
    );
    remove_stale_siblings(label);
    path
}

fn remove_stale_siblings(label: &str) {
    let prefix = format!("cerebellum-fixture-{label}-");
    let mut siblings = fs::read_dir("/tmp")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_str()?;
            let digest = name.strip_prefix(&prefix)?;
            if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return None;
            }
            let metadata = entry.metadata().ok()?;
            if metadata.is_dir() {
                Some((entry.path(), metadata.modified().ok()?))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    siblings.sort_by_key(|sibling| std::cmp::Reverse(sibling.1));
    let cutoff = SystemTime::now().checked_sub(Duration::from_secs(24 * 60 * 60));
    if let Some(cutoff) = cutoff {
        let old_siblings = siblings
            .into_iter()
            .filter(|(_, modified)| *modified < cutoff);
        for (path, _) in old_siblings.skip(3) {
            let _ = fs::remove_dir_all(path);
        }
    }
}

fn matches_fixture(path: &Path, bytes: &[u8], mode: u32) -> bool {
    fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o777 == mode)
        && fs::read(path).is_ok_and(|existing| existing == bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use std::time::SystemTime;

    fn set_directory_mtime(path: &Path, modified: SystemTime) {
        File::open(path)
            .expect("open fixture directory")
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .expect("set fixture directory mtime");
    }

    #[test]
    fn cleanup_removes_only_old_siblings_beyond_three_newest() {
        let label = format!("cleanup-test-{}", std::process::id());
        let prefix = format!("cerebellum-fixture-{label}-");
        let now = SystemTime::now();
        let old = now - Duration::from_secs(48 * 60 * 60);
        let mut paths = Vec::new();
        for (index, age) in [0, 1, 2, 3, 4].into_iter().enumerate() {
            let path = Path::new("/tmp").join(format!("{prefix}{index:064x}"));
            fs::create_dir_all(&path).expect("create old sibling");
            set_directory_mtime(&path, old - Duration::from_secs(age));
            paths.push(path);
        }
        let recent = Path::new("/tmp").join(format!("{prefix}{:064x}", 99));
        fs::create_dir_all(&recent).expect("create recent sibling");
        set_directory_mtime(&recent, now);
        let other_label =
            Path::new("/tmp").join(format!("cerebellum-fixture-other-{}", "a".repeat(64)));
        fs::create_dir_all(&other_label).expect("create other-label sibling");
        set_directory_mtime(&other_label, old);
        let malformed = Path::new("/tmp").join(format!("{prefix}{}g", "a".repeat(63)));
        fs::create_dir_all(&malformed).expect("create malformed sibling");
        set_directory_mtime(&malformed, old);

        remove_stale_siblings(&label);

        assert!(
            paths[..3].iter().all(|path| path.exists()),
            "three newest old siblings remain"
        );
        assert!(
            paths[3..].iter().all(|path| !path.exists()),
            "older siblings outside the three newest are removed"
        );
        assert!(recent.exists(), "recent sibling remains");
        assert!(other_label.exists(), "other label remains");
        assert!(malformed.exists(), "non-hex suffix remains");
        for path in paths.into_iter().chain([recent, other_label, malformed]) {
            let _ = fs::remove_dir_all(path);
        }
    }

    #[test]
    fn reuse_preserves_inode_and_mtime_and_repairs_wrong_bytes() {
        let first = content_named_fixture("reuse-inode-test", "fixture", b"first content", 0o700);
        let before = fs::metadata(&first).expect("first metadata");
        let same = content_named_fixture("reuse-inode-test", "fixture", b"first content", 0o700);
        let after = fs::metadata(&same).expect("reused metadata");
        assert_eq!(first, same);
        assert_eq!(
            before.ino(),
            after.ino(),
            "reuse must not replace the inode"
        );
        assert_eq!(
            (before.mtime(), before.mtime_nsec()),
            (after.mtime(), after.mtime_nsec())
        );

        let different =
            content_named_fixture("reuse-inode-test", "fixture", b"second content", 0o700);
        assert_ne!(first, different);

        // Corrupt the old fixture through a sibling rename, then require the
        // helper to replace it rather than accepting the correct path alone.
        let corrupt = first.parent().expect("fixture parent").join("corrupt-temp");
        fs::write(&corrupt, b"wrong bytes").expect("write corrupt fixture");
        fs::rename(&corrupt, &first).expect("install corrupt fixture");
        let corrupt_inode = fs::metadata(&first).expect("corrupt metadata").ino();
        let repaired =
            content_named_fixture("reuse-inode-test", "fixture", b"first content", 0o700);
        assert_eq!(repaired, first);
        assert_eq!(
            fs::read(&repaired).expect("repaired contents"),
            b"first content"
        );
        assert_ne!(
            fs::metadata(&repaired).expect("repaired metadata").ino(),
            corrupt_inode
        );
        assert_eq!(
            fs::metadata(&repaired)
                .expect("repaired mode")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
}
