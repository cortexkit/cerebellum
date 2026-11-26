use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use sha2::{Digest, Sha256};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
static HELD_FIXTURE_LOCKS: OnceLock<Mutex<HashMap<PathBuf, File>>> = OnceLock::new();
static PRUNE_FAILURES: AtomicUsize = AtomicUsize::new(0);

/// Keep fixture paths stable across test runs so macOS does not reassess a new
/// executable on every run. `/tmp` is intentional: codesign can hang during
/// system-policy evaluation of files under the per-user `$TMPDIR` on macOS 27.
/// Only the three newest copies are retained; a copy locked by a running test
/// remains available even when it is older than those three.
pub(crate) fn content_named_fixture(
    label: &str,
    file_name: &str,
    bytes: &[u8],
    mode: u32,
) -> PathBuf {
    content_named_fixture_with_miss_hook(label, file_name, bytes, mode, || {})
}

fn content_named_fixture_with_miss_hook(
    label: &str,
    file_name: &str,
    bytes: &[u8],
    mode: u32,
    on_miss: impl FnOnce(),
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
    hold_fixture_lock(&directory).expect("lock content-named fixture");
    fs::create_dir_all(&directory).expect("create content-named fixture directory");
    let path = directory.join(file_name);
    if !matches_fixture(&path, bytes, mode) {
        on_miss();
        publish_fixture(&directory, file_name, &path, bytes, mode);
    }
    remove_stale_siblings(label);
    path
}

fn publish_fixture(directory: &Path, file_name: &str, path: &Path, bytes: &[u8], mode: u32) {
    // The shared fixture lease prevents pruning but allows concurrent callers.
    // Recheck under a writer lock so a second publisher does not unlink an
    // executable a child may already be running.
    let writer_lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory.join(".publish.lock"))
        .expect("open fixture writer lock");
    writer_lock.lock().expect("lock fixture for publication");
    if matches_fixture(path, bytes, mode) {
        return;
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
        fs::rename(&temporary_path, path)?;
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary_path);
        panic!("write content-named fixture: {error}");
    }
    assert!(
        matches_fixture(path, bytes, mode),
        "fixture content or mode changed after write"
    );
}

fn remove_stale_siblings(label: &str) {
    let prefix = format!("cerebellum-fixture-{label}-");
    let entries = match fs::read_dir("/tmp") {
        Ok(entries) => entries,
        Err(_) => {
            count_prune_failure();
            return;
        }
    };
    let mut siblings = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                count_prune_failure();
                continue;
            }
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(digest) = name.strip_prefix(&prefix) else {
            continue;
        };
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => {
                count_prune_failure();
                continue;
            }
        };
        if !metadata.is_dir() {
            continue;
        }
        let modified = match metadata.modified() {
            Ok(modified) => modified,
            Err(_) => {
                count_prune_failure();
                continue;
            }
        };
        siblings.push((entry.path(), modified));
    }
    siblings.sort_by_key(|sibling| std::cmp::Reverse(sibling.1));
    for (path, _) in siblings.into_iter().skip(3) {
        let lock_file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(fixture_lock_path(&path))
        {
            Ok(file) => file,
            Err(_) => {
                count_prune_failure();
                continue;
            }
        };
        match lock_file.try_lock() {
            Ok(()) => {
                if fs::remove_dir_all(path).is_err() {
                    count_prune_failure();
                }
            }
            Err(std::fs::TryLockError::WouldBlock) => {}
            Err(std::fs::TryLockError::Error(_)) => count_prune_failure(),
        }
    }
}

fn hold_fixture_lock(directory: &Path) -> std::io::Result<()> {
    let lock_path = fixture_lock_path(directory);
    let mut held = HELD_FIXTURE_LOCKS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if held.contains_key(&lock_path) {
        return Ok(());
    }
    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    lock_file.lock_shared()?;
    held.insert(lock_path, lock_file);
    Ok(())
}

fn fixture_lock_path(directory: &Path) -> PathBuf {
    Path::new("/tmp").join(format!(
        ".{}.lock",
        directory
            .file_name()
            .expect("fixture directory has a name")
            .to_string_lossy()
    ))
}

fn count_prune_failure() {
    PRUNE_FAILURES.fetch_add(1, Ordering::Relaxed);
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
    use std::sync::mpsc;
    use std::time::{Duration, SystemTime};

    fn set_directory_mtime(path: &Path, modified: SystemTime) {
        File::open(path)
            .expect("open fixture directory")
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .expect("set fixture directory mtime");
    }

    #[test]
    fn cleanup_keeps_only_three_newest_recent_siblings() {
        let label = format!("cleanup-test-{}", std::process::id());
        let prefix = format!("cerebellum-fixture-{label}-");
        let now = SystemTime::now();
        let mut paths = Vec::new();
        for index in 0..10 {
            let path = Path::new("/tmp").join(format!("{prefix}{index:064x}"));
            fs::create_dir_all(&path).expect("create recent sibling");
            set_directory_mtime(&path, now - Duration::from_secs(index));
            paths.push(path);
        }
        let other_label =
            Path::new("/tmp").join(format!("cerebellum-fixture-other-{}", "a".repeat(64)));
        fs::create_dir_all(&other_label).expect("create other-label sibling");
        set_directory_mtime(&other_label, now - Duration::from_secs(100));
        let malformed = Path::new("/tmp").join(format!("{prefix}{}g", "a".repeat(63)));
        fs::create_dir_all(&malformed).expect("create malformed sibling");
        set_directory_mtime(&malformed, now - Duration::from_secs(100));

        remove_stale_siblings(&label);

        assert!(
            paths[..3].iter().all(|path| path.exists()),
            "three newest siblings remain"
        );
        assert!(
            paths[3..].iter().all(|path| !path.exists()),
            "all siblings after the three newest are removed"
        );
        assert!(other_label.exists(), "other label remains");
        assert!(malformed.exists(), "non-hex suffix remains");
        for path in paths.iter().chain([&other_label, &malformed]) {
            let _ = fs::remove_dir_all(path);
            let _ = fs::remove_file(fixture_lock_path(path));
        }
    }

    #[test]
    fn cleanup_never_removes_a_held_oldest_sibling() {
        let label = format!("held-cleanup-test-{}", std::process::id());
        let prefix = format!("cerebellum-fixture-{label}-");
        let now = SystemTime::now();
        let paths = (0..5)
            .map(|index| {
                let path = Path::new("/tmp").join(format!("{prefix}{index:064x}"));
                fs::create_dir_all(&path).expect("create sibling");
                set_directory_mtime(&path, now - Duration::from_secs(index));
                path
            })
            .collect::<Vec<_>>();
        let held_path = &paths[4];
        let held_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(fixture_lock_path(held_path))
            .expect("open oldest sibling lock");
        held_file.lock_shared().expect("hold oldest sibling lock");

        remove_stale_siblings(&label);

        assert!(paths[0..3].iter().all(|path| path.exists()));
        assert!(!paths[3].exists(), "unheld old sibling is removed");
        assert!(held_path.exists(), "a live process keeps its fixture copy");
        drop(held_file);
        for path in &paths {
            let _ = fs::remove_dir_all(path);
            let _ = fs::remove_file(fixture_lock_path(path));
        }
    }

    #[test]
    fn cleanup_never_removes_the_current_process_fixture() {
        let label = format!("current-cleanup-test-{}", std::process::id());
        let current = content_named_fixture(&label, "fixture", b"current fixture", 0o600);
        let now = SystemTime::now();
        set_directory_mtime(
            current.parent().expect("current fixture directory"),
            now - Duration::from_secs(30),
        );
        let prefix = format!("cerebellum-fixture-{label}-");
        let mut newer = Vec::new();
        for index in 0..3 {
            let path = Path::new("/tmp").join(format!("{prefix}{:064x}", 100 + index));
            fs::create_dir_all(&path).expect("create newer sibling");
            set_directory_mtime(&path, now - Duration::from_secs(index));
            newer.push(path);
        }

        remove_stale_siblings(&label);

        assert!(
            current.exists(),
            "the fixture returned to this process survives"
        );
        assert!(newer.iter().all(|path| path.exists()));
        for path in newer
            .iter()
            .map(|path| path.as_path())
            .chain([current.parent().expect("current fixture directory")])
        {
            let _ = fs::remove_dir_all(path);
            let _ = fs::remove_file(fixture_lock_path(path));
        }
    }

    #[test]
    fn concurrent_publishers_preserve_the_first_fixture_inode() {
        let label = format!(
            "concurrent-publish-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let bytes = b"same bytes from both publishers";
        std::thread::scope(|scope| {
            let (missed_tx, missed_rx) = mpsc::channel();
            let (resume_tx, resume_rx) = mpsc::channel();
            let label = label.as_str();
            let second = scope.spawn(move || {
                content_named_fixture_with_miss_hook(label, "fixture", bytes, 0o700, || {
                    missed_tx.send(()).expect("report cache miss");
                    resume_rx.recv().expect("wait for the first publication");
                })
            });

            // Both publishers see an empty cache. Let the first finish before
            // the other resumes, just as a child can start from the first copy.
            missed_rx.recv().expect("second publisher saw the miss");
            let first = content_named_fixture(label, "fixture", bytes, 0o700);
            let opened = File::open(&first).expect("open first publication");
            resume_tx.send(()).expect("resume second publisher");
            let same = second.join().expect("second publisher finished");
            let first_inode = opened.metadata().expect("first inode").ino();
            let published_inode = fs::metadata(&same).expect("published inode").ino();
            drop(opened);

            let directory = first.parent().expect("fixture directory");
            fs::remove_dir_all(directory).expect("remove test fixture");
            fs::remove_file(fixture_lock_path(directory)).expect("remove test fixture lock");
            assert_eq!(first, same);
            assert_eq!(
                published_inode, first_inode,
                "a second publisher must not replace the first executable inode"
            );
        });
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
