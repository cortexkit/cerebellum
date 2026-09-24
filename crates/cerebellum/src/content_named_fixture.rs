use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// Keep fixture paths stable across test runs so macOS does not reassess a new
/// executable on every run. `/tmp` is intentional: codesign can hang during
/// system-policy evaluation of files under the per-user `$TMPDIR` on macOS 27.
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
    path
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
