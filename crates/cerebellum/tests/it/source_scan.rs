//! Shared pieces of the structural source scans in `one_lease_clock` and
//! `one_launch_nonce_reader`: a tokenizer that makes their matching blind to
//! layout, and the scratch-tree helpers their walk controls use.

use std::path::{Path, PathBuf};

/// Splits numbered lines into tokens, each with the 1-based number of the line
/// it starts on: identifiers (letters, digits and `_`), the path separator
/// `::`, and every other non-space character on its own.
///
/// Whitespace and line breaks only separate tokens, so `SystemClock::new ()`,
/// a call split over several lines and the tidy one-line form all produce the
/// same sequence. Comments and string literals are not recognised: the words
/// inside them come out as ordinary tokens, which keeps the scans flagging a
/// mention there as they always have.
pub fn tokens<'a>(lines: &[(usize, &'a str)]) -> Vec<(usize, &'a str)> {
    let is_identifier = |c: char| c.is_alphanumeric() || c == '_';
    let mut found = Vec::new();
    for &(line_number, line) in lines {
        let mut rest = line;
        while let Some(first) = rest.chars().next() {
            let length = if first.is_whitespace() {
                rest = &rest[first.len_utf8()..];
                continue;
            } else if is_identifier(first) {
                rest.find(|c: char| !is_identifier(c)).unwrap_or(rest.len())
            } else if rest.starts_with("::") {
                2
            } else {
                first.len_utf8()
            };
            found.push((line_number, &rest[..length]));
            rest = &rest[length..];
        }
    }
    found
}

/// A fresh directory under the system temp directory. The walk controls only
/// ever put copied source text in it, never anything executed.
pub fn scratch_directory(label: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "cerebellum-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the clock is after the epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(&directory).expect("create a scratch directory");
    directory
}

/// Copies a directory tree, files and subdirectories, into `to`.
pub fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("create a copy directory");
    for entry in std::fs::read_dir(from).expect("list a directory to copy") {
        let path = entry.expect("directory entry").path();
        let target = to.join(path.file_name().expect("an entry has a name"));
        if path.is_dir() {
            copy_tree(&path, &target);
        } else {
            std::fs::copy(&path, &target).expect("copy a source file");
        }
    }
}
