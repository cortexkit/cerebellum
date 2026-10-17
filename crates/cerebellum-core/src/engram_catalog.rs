//! The backup catalog this module writes into its own data directory.
//!
//! The fleet's backup module (engram) backs up a module's data only when the
//! module's data directory holds an `engram-catalog.json` declaring what each
//! part of that data is: `portable` (moved to a new machine), `device-local`
//! (kept on this machine only) or `excluded` (deliberately never backed up,
//! with a reason). A directory with no catalog is skipped, so a module whose
//! catalog has to be copied in by hand is uncovered on every machine where
//! nobody did that. This module therefore writes its catalog itself, at
//! production startup.
//!
//! The content is the repository's `engram-catalog.json`, compiled into the
//! binary, so the reviewed declaration and the written file cannot differ.
//! The bytes are the same on every write: no timestamp, no host detail, and
//! the key order is the file's. That lets a start that finds the same bytes
//! on disk leave the file alone, and lets a backup that hashes the file see
//! no change where nothing changed.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// The file name engram looks for in each module's data directory.
pub const CATALOG_FILE: &str = "engram-catalog.json";

/// The declaration, as reviewed in the repository root.
const CATALOG: &str = include_str!("../../../engram-catalog.json");

/// Distinguishes temporary files when one process writes more than once.
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// The exact bytes written to disk.
pub fn catalog_bytes() -> Vec<u8> {
    CATALOG.as_bytes().to_vec()
}

/// What [`write_catalog`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogWrite {
    /// The file already held these bytes and was not touched.
    Unchanged,
    /// The file was missing or different and was replaced.
    Written,
}

/// Where the catalog lives inside a module data directory.
pub fn catalog_path(module_directory: &Path) -> PathBuf {
    module_directory.join(CATALOG_FILE)
}

/// Make `module_directory/engram-catalog.json` hold [`catalog_bytes`].
///
/// The directory is passed in rather than resolved here, so a test writes
/// into a scratch directory and never into the operator's data home; only the
/// production startup path resolves the real one.
///
/// A file that already holds the same bytes is left alone, so its modified
/// time keeps meaning "the declaration last changed then". Otherwise the
/// bytes go to a temporary file in the same directory, which is renamed over
/// the catalog: a crash leaves the old catalog or the new one, never half of
/// one, which engram would refuse as malformed.
pub fn write_catalog(module_directory: &Path) -> io::Result<CatalogWrite> {
    let bytes = catalog_bytes();
    let path = catalog_path(module_directory);
    match fs::read(&path) {
        Ok(existing) if existing == bytes => return Ok(CatalogWrite::Unchanged),
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    crate::private_fs::create_dir_all(module_directory)?;
    let temporary = module_directory.join(format!(
        ".{CATALOG_FILE}.{}.{}.tmp",
        std::process::id(),
        TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let written = (|| {
        let mut file = crate::private_fs::create_new_file(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &path)?;
        sync_directory(module_directory)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    written.map(|()| CatalogWrite::Written)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}

/// Directories cannot be opened for syncing on this platform; the rename is
/// the durable step there.
#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::time::{Duration, SystemTime};

    /// A fresh directory under the system temp dir, removed on drop, so no
    /// test here ever writes the operator's data home.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "cerebellum-engram-catalog-{label}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            Self(path)
        }

        /// A module directory that does not exist yet, as on a fresh machine.
        fn module(&self) -> PathBuf {
            self.0.join("cortexkit").join("cerebellum")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    // A copy of the descriptor shape engram parses (engram-core's
    // `catalog.rs`), kept here because that crate is not a dependency of
    // this workspace. The enums list exactly the names engram accepts, so an
    // unknown class or mechanism fails to parse here as it is refused there.
    #[derive(serde::Deserialize)]
    struct Descriptor {
        schema_version: u32,
        module_id: String,
        entries: Vec<Entry>,
    }

    #[derive(serde::Deserialize)]
    struct Entry {
        entry_id: String,
        class: Class,
        #[serde(default)]
        reason: Option<String>,
        mechanism: Mechanism,
        #[serde(default)]
        path: Option<String>,
    }

    #[derive(serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
    #[serde(rename_all = "kebab-case")]
    enum Class {
        Portable,
        DeviceLocal,
        Rebuild,
        Excluded,
    }

    #[derive(serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
    #[serde(rename_all = "kebab-case")]
    enum Mechanism {
        WholeDb,
        PageDb,
        OwnerExport,
        Filetree,
        LogStream,
    }

    /// Engram's path rule: relative to the module directory, `/`-separated,
    /// and every component a real name (no empty, `.`, `..`, backslash or
    /// drive prefix), so the path means the same on every host.
    fn engram_accepts_path(path: &str) -> bool {
        let bytes = path.as_bytes();
        let drive_prefix = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
        !path.contains('\\')
            && !drive_prefix
            && !Path::new(path).is_absolute()
            && path
                .split('/')
                .all(|component| !component.is_empty() && component != "." && component != "..")
    }

    fn parsed() -> Descriptor {
        serde_json::from_slice(&catalog_bytes()).expect("the catalog parses as engram's descriptor")
    }

    /// The rules engram's planner applies before it captures anything; a
    /// catalog that breaks one is refused whole and the module is skipped.
    #[test]
    fn the_catalog_passes_engrams_descriptor_rules() {
        let descriptor = parsed();
        assert_eq!(descriptor.schema_version, 1, "engram reads schema 1 only");
        assert_eq!(
            descriptor.module_id, "cerebellum",
            "engram refuses a catalog whose module id is not its directory name"
        );
        let mut ids = BTreeSet::new();
        for entry in &descriptor.entries {
            assert!(
                ids.insert(entry.entry_id.as_str()),
                "duplicate entry id {}",
                entry.entry_id
            );
            if entry.class == Class::Excluded {
                assert!(
                    entry
                        .reason
                        .as_deref()
                        .is_some_and(|r| !r.trim().is_empty()),
                    "{}: an excluded entry needs a reason",
                    entry.entry_id
                );
                assert!(
                    entry.path.is_some(),
                    "{}: an excluded entry needs a path",
                    entry.entry_id
                );
            }
            // Engram only refuses a bad path on excluded and portable
            // entries; requiring a good one everywhere keeps every declared
            // path meaningful to its drift checks.
            let path = entry.path.as_deref().expect("every entry names its tree");
            assert!(
                engram_accepts_path(path),
                "{}: path {path:?}",
                entry.entry_id
            );
            assert!(
                matches!(
                    entry.mechanism,
                    Mechanism::Filetree | Mechanism::WholeDb | Mechanism::PageDb
                ),
                "{}: {:?} has no capture path in engram",
                entry.entry_id,
                entry.mechanism
            );
        }
    }

    /// Nothing this module keeps should follow the operator to another
    /// machine: browser sessions are secrets bound to this one, and grants
    /// and the audit trail describe this machine. Each tree the module
    /// writes under its data directory is declared, so none is left to read
    /// as an oversight.
    #[test]
    fn the_catalog_declares_every_tree_and_nothing_portable() {
        let descriptor = parsed();
        let by_path: Vec<_> = descriptor
            .entries
            .iter()
            .map(|entry| (entry.path.as_deref().unwrap_or(""), entry.class))
            .collect();
        assert_eq!(
            by_path,
            [
                ("browser", Class::Excluded),
                ("journal", Class::DeviceLocal)
            ]
        );
        let browser = &descriptor.entries[0];
        assert!(
            browser
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("signed-in browser sessions")),
            "the browser exclusion says why: {:?}",
            browser.reason
        );
    }

    /// Byte-identical output is what lets an unchanged start leave the file
    /// alone and a backup see no change. A timestamp or anything else that
    /// varies between writes breaks it.
    #[test]
    fn two_writes_produce_identical_bytes() {
        let first = Scratch::new("first");
        let second = Scratch::new("second");
        assert_eq!(
            write_catalog(&first.module()).unwrap(),
            CatalogWrite::Written
        );
        assert_eq!(
            write_catalog(&second.module()).unwrap(),
            CatalogWrite::Written
        );
        let first_bytes = fs::read(catalog_path(&first.module())).unwrap();
        let second_bytes = fs::read(catalog_path(&second.module())).unwrap();
        assert_eq!(first_bytes, second_bytes);
        assert_eq!(first_bytes, CATALOG.as_bytes());
    }

    /// A start that finds the same bytes must not rewrite them: the modified
    /// time is pinned to a day in 2001 first, and must still read that day.
    #[test]
    fn an_unchanged_catalog_is_not_rewritten() {
        let scratch = Scratch::new("unchanged");
        let module = scratch.module();
        assert_eq!(write_catalog(&module).unwrap(), CatalogWrite::Written);
        let pinned = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        fs::File::options()
            .write(true)
            .open(catalog_path(&module))
            .unwrap()
            .set_modified(pinned)
            .unwrap();
        assert_eq!(write_catalog(&module).unwrap(), CatalogWrite::Unchanged);
        let modified = fs::metadata(catalog_path(&module))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(modified, pinned);
    }

    /// A stale or hand-edited catalog is replaced whole, owner-only, and no
    /// temporary file is left beside it.
    #[test]
    fn a_different_catalog_is_replaced_without_leftovers() {
        let scratch = Scratch::new("replaced");
        let module = scratch.module();
        crate::private_fs::create_dir_all(&module).unwrap();
        let stale = br#"{"schema_version":1,"module_id":"cerebellum","entries":[]}"#;
        crate::private_fs::create_file(&catalog_path(&module))
            .unwrap()
            .write_all(stale)
            .unwrap();
        assert_eq!(write_catalog(&module).unwrap(), CatalogWrite::Written);
        assert_ne!(fs::read(catalog_path(&module)).unwrap(), stale);
        let names: Vec<_> = fs::read_dir(&module)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, [CATALOG_FILE]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(catalog_path(&module))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    /// A failure is returned, not panicked, so startup can count it and go
    /// on. A file where the module directory should be makes the write fail.
    #[test]
    fn a_write_that_cannot_happen_returns_an_error() {
        let scratch = Scratch::new("blocked");
        let module = scratch.module();
        crate::private_fs::create_dir_all(module.parent().unwrap()).unwrap();
        crate::private_fs::create_file(&module).unwrap();
        assert!(write_catalog(&module).is_err());
    }
}
