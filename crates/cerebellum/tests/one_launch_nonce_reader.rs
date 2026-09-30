//! The launch nonce has exactly one reader: `crates/cerebellum/src/launch_nonce.rs`.
//!
//! The daemon passes the nonce on a pipe, and during the move also as the
//! `SUBC_LAUNCH_NONCE` environment variable. It removes the variable once every
//! module reads only the pipe. `launch_nonce_source: fd` in provenance proves
//! that HELLO read the pipe, but not that nothing else still reads the
//! variable. Other modules had such second readers, which would have failed
//! the day the variable went away. This scan keeps cerebellum from growing
//! one: any mention of the nonce's variables or accessor outside that one file
//! fails here.

use std::path::{Path, PathBuf};

/// The one file allowed to read the nonce.
const READER: &str = "crates/cerebellum/src/launch_nonce.rs";

/// Mentions allowed elsewhere, each with the reason it is not a read.
const ALLOWED_MENTIONS: &[(&str, &str)] = &[(
    "crates/cerebellum/src/browser_launch_service.rs",
    "a test feeding the variables into the browser's explicit environment \
     builder and expecting them dropped",
)];

const PATTERNS: &[&str] = &[
    "SUBC_LAUNCH_NONCE",
    "LAUNCH_NONCE_ENV",
    "LAUNCH_NONCE_FD_ENV",
    "launch_nonce()",
];

#[test]
fn only_launch_nonce_rs_reads_the_launch_nonce() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the crate sits two levels under the workspace root");
    let mut sources = Vec::new();
    for entry in std::fs::read_dir(workspace.join("crates")).expect("list crates") {
        let src = entry.expect("crate entry").path().join("src");
        if src.is_dir() {
            collect_rust_sources(&src, &mut sources);
        }
    }
    assert!(
        sources.len() > 20,
        "the scan saw {} files; a broken walk would pass an empty scan",
        sources.len()
    );

    let mut reader_mentions = 0;
    let mut offending = Vec::new();
    for file in &sources {
        let relative = file
            .strip_prefix(workspace)
            .expect("sources live under the workspace")
            .to_string_lossy()
            .replace('\\', "/");
        let source = std::fs::read_to_string(file).expect("read a source file");
        for (index, line) in source.lines().enumerate() {
            if !PATTERNS.iter().any(|pattern| line.contains(pattern)) {
                continue;
            }
            if relative == READER {
                reader_mentions += 1;
            } else if !ALLOWED_MENTIONS.iter().any(|(path, _)| *path == relative) {
                offending.push(format!("{relative}:{}: {}", index + 1, line.trim()));
            }
        }
    }

    // The control: the real reader must be seen, or the patterns no longer
    // match what reading the nonce looks like and a clean result means nothing.
    assert!(
        reader_mentions > 0,
        "{READER} no longer matches any pattern; update PATTERNS to what a read looks like"
    );
    assert!(
        offending.is_empty(),
        "the launch nonce must be read only through {READER}, found:\n{}",
        offending.join("\n")
    );
}

fn collect_rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("list a source directory") {
        let path = entry.expect("source entry").path();
        if path.is_dir() {
            collect_rust_sources(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}
