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

/// What an actual read looks like in [`READER`]. The real-tree scan insists on
/// finding it there, so a reader that moved or stopped reading fails the scan
/// instead of leaving it to pass over nothing.
const READER_READ: &str = "subc_os::launch_nonce()";

/// The fewest `.rs` files the real-tree walk may read and still pass. The
/// workspace had 147 under its crates' `src` directories when this was set;
/// the floor sits well below that so ordinary churn never trips it, while a
/// walk pointed at the wrong root, or one that stopped descending, falls under
/// it even if it still reaches the reader.
const MIN_FILES_SCANNED: usize = 100;

#[test]
fn only_launch_nonce_rs_reads_the_launch_nonce() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the crate sits two levels under the workspace root");
    let scan = scan_workspace(workspace);

    assert!(
        scan.files_scanned >= MIN_FILES_SCANNED,
        "the scan read {} files, below the floor of {MIN_FILES_SCANNED}, so it is \
         not looking at the whole workspace and a clean result proves nothing",
        scan.files_scanned
    );
    // The control: the real reader must be seen reading, or the patterns no
    // longer match what reading the nonce looks like and a clean result means
    // nothing.
    assert!(
        scan.reader_reads > 0,
        "{READER} has no line matching {READER_READ:?}; if the reader moved or \
         reads differently now, update READER, READER_READ and PATTERNS to match"
    );
    assert!(
        scan.violations.is_empty(),
        "the launch nonce must be read only through {READER}, found:\n{}",
        scan.violations.join("\n")
    );
}

/// What one walk over the workspace's crate sources found.
struct TreeScan {
    files_scanned: usize,
    /// Lines in [`READER`] that match the patterns and contain [`READER_READ`].
    reader_reads: usize,
    /// Forbidden mentions, as `path:line: text`.
    violations: Vec<String>,
}

/// Walks every `.rs` file under `workspace/crates/*/src` and runs the detector
/// on each, with paths reported relative to `workspace`.
fn scan_workspace(workspace: &Path) -> TreeScan {
    let mut sources = Vec::new();
    for entry in std::fs::read_dir(workspace.join("crates")).expect("list crates") {
        let src = entry.expect("crate entry").path().join("src");
        if src.is_dir() {
            collect_rust_sources(&src, &mut sources);
        }
    }
    let mut scan = TreeScan {
        files_scanned: sources.len(),
        reader_reads: 0,
        violations: Vec::new(),
    };
    for file in &sources {
        let relative = file
            .strip_prefix(workspace)
            .expect("sources live under the workspace")
            .to_string_lossy()
            .replace('\\', "/");
        let source = std::fs::read_to_string(file).expect("read a source file");
        if relative == READER {
            scan.reader_reads += mentions(&source)
                .iter()
                .filter(|(_, line)| line.contains(READER_READ))
                .count();
        }
        scan.violations.extend(nonce_violations(&relative, &source));
    }
    scan
}

/// Every mention of the nonce in one file that the fence forbids, each as
/// `path:line: text`. `path` is relative to the workspace root.
///
/// The reader and the files in [`ALLOWED_MENTIONS`] may mention it freely;
/// every mention anywhere else is a violation, test code included, since the
/// scan has no notion of test modules.
fn nonce_violations(path: &str, source: &str) -> Vec<String> {
    if path == READER || ALLOWED_MENTIONS.iter().any(|(allowed, _)| *allowed == path) {
        return Vec::new();
    }
    mentions(source)
        .into_iter()
        .map(|(line_number, line)| format!("{path}:{line_number}: {}", line.trim()))
        .collect()
}

/// Every line naming the nonce's variables or accessor, with its 1-based number.
fn mentions(source: &str) -> Vec<(usize, &str)> {
    source
        .lines()
        .enumerate()
        .filter(|(_, line)| PATTERNS.iter().any(|pattern| line.contains(pattern)))
        .map(|(index, line)| (index + 1, line))
        .collect()
}

/// A file outside the reader and the allowed list, for planted source.
const ELSEWHERE: &str = "crates/cerebellum/src/consent.rs";

/// One planted read per spelling in [`PATTERNS`], through `std::env::var`,
/// `std::env::var_os` and the accessor.
const READS: &[&str] = &[
    "let nonce = std::env::var(\"SUBC_LAUNCH_NONCE\");",
    "let fd = std::env::var_os(\"SUBC_LAUNCH_NONCE_FD\");",
    "let nonce = std::env::var(subc_os::LAUNCH_NONCE_ENV);",
    "let fd = std::env::var_os(subc_os::LAUNCH_NONCE_FD_ENV);",
    "let nonce = subc_os::launch_nonce();",
];

/// The fence's positive control: planted reads of the nonce the detector must
/// flag.
///
/// The real-tree test passes on a clean tree and on a detector that has gone
/// blind alike, so on its own a green result proves nothing. Every spelling in
/// [`PATTERNS`] is planted, so dropping or breaking one fails here.
#[test]
fn the_nonce_detector_flags_every_planted_read() {
    for read in READS {
        let source = ["fn hello() {", read, "}"].join("\n");
        assert_flags(
            &format!("{read:?} outside the reader"),
            ELSEWHERE,
            &source,
            &[2],
        );
        // The scan does not skip test modules, so a test outside the reader
        // that touches the nonce is flagged like any other line.
        let in_test_module = [
            "#[cfg(test)]",
            "mod tests {",
            "    fn reads() {",
            read,
            "    }",
            "}",
        ]
        .join("\n");
        assert_flags(
            &format!("{read:?} inside a test module outside the reader"),
            ELSEWHERE,
            &in_test_module,
            &[4],
        );
    }
    // None of these reads the nonce, but the scanner matches text on the line
    // and cannot tell a read from a removal, a deny list, a comment or a
    // message, so each is flagged outside the reader. Pinned so that narrowing
    // the rule is a decision someone makes here, not a side effect; today such
    // a line belongs in the reader or in ALLOWED_MENTIONS with its reason.
    let non_reads = [
        "command.env_remove(subc_os::LAUNCH_NONCE_ENV);",
        "std::env::remove_var(\"SUBC_LAUNCH_NONCE_FD\");",
        "const DENIED: &[&str] = &[\"SUBC_LAUNCH_NONCE\", \"SUBC_LAUNCH_NONCE_FD\"];",
        "// The daemon hands the nonce over in SUBC_LAUNCH_NONCE.",
        "tracing::warn!(\"SUBC_LAUNCH_NONCE is still set\");",
    ];
    for line in non_reads {
        let source = ["fn hello() {", line, "}"].join("\n");
        assert_flags(
            &format!("{line:?}, a non-read the scanner flags"),
            ELSEWHERE,
            &source,
            &[2],
        );
    }
}

/// The fence's negative control: planted source the detector must pass.
///
/// A detector that flags too much, such as every environment read or the reader
/// itself, tends to get loosened by hand until the tree passes. These cases pin
/// what is not a violation, so over-matching fails here by name.
#[test]
fn the_nonce_detector_passes_every_planted_non_read() {
    for read in READS {
        let source = ["fn hello() {", read, "}"].join("\n");
        assert_flags(&format!("{read:?} in the reader"), READER, &source, &[]);
        for (allowed, _) in ALLOWED_MENTIONS {
            assert_flags(
                &format!("{read:?} in an allowed file"),
                allowed,
                &source,
                &[],
            );
        }
    }
    // Near misses outside the reader: other environment variables, including
    // one sharing the prefix, and code that names the reader module without
    // calling the accessor.
    assert_flags(
        "code that does not touch the nonce",
        ELSEWHERE,
        &[
            "mod launch_nonce;",
            "fn hello() {",
            "    let home = std::env::var(\"HOME\");",
            "    let id = std::env::var_os(\"SUBC_LAUNCH_ID\");",
            "    launch_nonce::scrub_child_environment(&mut command);",
            "    let proof = handoff.nonce();",
            "}",
        ]
        .join("\n"),
        &[],
    );
}

/// The walk's control: the real-tree scan's own walk, run over a copy of every
/// crate's `src` with one violating file planted two directories down.
///
/// The snippet controls exercise the detector on text handed to it, and the
/// premise check only proves the walk reaches the reader. Neither notices a
/// walk that stops descending into module directories or reads the wrong file
/// extension; this does.
#[test]
fn the_tree_walk_reports_a_planted_file_in_a_nested_module() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the crate sits two levels under the workspace root");
    let scratch = scratch_directory("launch-nonce-walk");
    for entry in std::fs::read_dir(workspace.join("crates")).expect("list crates") {
        let crate_dir = entry.expect("crate entry").path();
        let src = crate_dir.join("src");
        if src.is_dir() {
            let name = crate_dir.file_name().expect("a crate directory has a name");
            copy_tree(&src, &scratch.join("crates").join(name).join("src"));
        }
    }
    let nested = scratch.join("crates/cerebellum/src/planted/deeper");
    std::fs::create_dir_all(&nested).expect("create the planted module directory");
    let planted = "pub fn second() { let _ = std::env::var(\"SUBC_LAUNCH_NONCE\"); }\n";
    std::fs::write(nested.join("second_reader.rs"), planted).expect("plant the violation");
    // The same text in a file that is not Rust source must not be read.
    std::fs::write(nested.join("second_reader.txt"), planted).expect("plant the decoy");

    let scan = scan_workspace(&scratch);
    let _ = std::fs::remove_dir_all(&scratch);

    assert_eq!(
        scan.violations,
        ["crates/cerebellum/src/planted/deeper/second_reader.rs:1: \
          pub fn second() { let _ = std::env::var(\"SUBC_LAUNCH_NONCE\"); }"],
        "the walk must report the planted .rs file by path, and only it"
    );
    assert!(
        scan.reader_reads > 0,
        "the copied tree still holds the reader, so the walk must find it"
    );
}

/// Runs the detector over planted source and asserts exactly `expected` (1-based
/// line numbers) are flagged.
fn assert_flags(case: &str, path: &str, source: &str, expected: &[usize]) {
    let violations = nonce_violations(path, source);
    let flagged: Vec<usize> = violations
        .iter()
        .map(|violation| {
            violation
                .split(':')
                .nth(1)
                .and_then(|number| number.parse().ok())
                .expect("a violation reads path:line: text")
        })
        .collect();
    assert_eq!(
        flagged, expected,
        "case {case:?}: the detector flagged the wrong lines: {violations:?}"
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

/// A fresh directory under the system temp directory. It only ever holds
/// copied source text, never anything executed.
fn scratch_directory(label: &str) -> PathBuf {
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
fn copy_tree(from: &Path, to: &Path) {
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
