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

use crate::support::source_scan::{self, copy_tree, scratch_directory};

/// The one file allowed to read the nonce.
const READER: &str = "crates/cerebellum/src/launch_nonce.rs";

/// Mentions allowed elsewhere, each with the reason it is not a read.
const ALLOWED_MENTIONS: &[(&str, &str)] = &[(
    "crates/cerebellum/src/browser_launch_service.rs",
    "a test feeding the variables into the browser's explicit environment \
     builder and expecting them dropped",
)];

/// Text that marks an identifier as naming the nonce's environment variables:
/// the variable names themselves (which `SUBC_LAUNCH_NONCE_FD` contains too)
/// and `subc_os`'s constants for them.
const VARIABLE_NAMES: &[&str] = &[
    "SUBC_LAUNCH_NONCE",
    "LAUNCH_NONCE_ENV",
    "LAUNCH_NONCE_FD_ENV",
];

/// The accessor `subc_os` reads the nonce through.
const ACCESSOR: &str = "launch_nonce";

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
         reads differently now, update READER, READER_READ and the detector to match"
    );
    // An allowance that no longer covers anything would quietly excuse the
    // next mention someone adds to that file, so each must still be in use.
    assert!(
        scan.unused_allowances.is_empty(),
        "these ALLOWED_MENTIONS entries no longer mention the nonce; remove them \
         so they cannot excuse a new read:\n{}",
        scan.unused_allowances.join("\n")
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
    /// Lines in [`READER`] that the detector matches and that contain
    /// [`READER_READ`].
    reader_reads: usize,
    /// [`ALLOWED_MENTIONS`] paths the walk did not find, or found with no
    /// mention left in them.
    unused_allowances: Vec<String>,
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
        unused_allowances: Vec::new(),
        violations: Vec::new(),
    };
    let mut allowance_used = vec![false; ALLOWED_MENTIONS.len()];
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
        for (used, (path, _)) in allowance_used.iter_mut().zip(ALLOWED_MENTIONS) {
            if *path == relative && !mentions(&source).is_empty() {
                *used = true;
            }
        }
        scan.violations.extend(nonce_violations(&relative, &source));
    }
    for (used, (path, reason)) in allowance_used.iter().zip(ALLOWED_MENTIONS) {
        if !used {
            scan.unused_allowances.push(format!("{path}: {reason}"));
        }
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

/// Every line naming the nonce's variables or accessor, with its 1-based number
/// and text. A mention split over several lines is reported on the line where
/// the name sits.
///
/// Matched on tokens rather than text, so layout cannot hide a read. A
/// variable is named by any identifier containing one of [`VARIABLE_NAMES`],
/// which covers the quoted name, `subc_os`'s constants, and a `const` the name
/// is stashed in (flagged where the name is written). The accessor is named
/// when it is called, with any spacing or line break before the parenthesis,
/// and when `subc_os::launch_nonce` is
/// referenced or renamed without a call, as an import or a function value.
/// The module `launch_nonce` and paths through it are not the accessor.
///
/// Comments and string literals are not parsed, so a mention in either counts
/// as well, as it did when this was a plain text match.
fn mentions(source: &str) -> Vec<(usize, &str)> {
    let lines: Vec<(usize, &str)> = source
        .lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line))
        .collect();
    let tokens = source_scan::tokens(&lines);
    let token_at = |index: usize| tokens.get(index).map(|(_, token)| *token);
    let mut found: Vec<(usize, &str)> = Vec::new();
    for (index, &(line_number, token)) in tokens.iter().enumerate() {
        let names_variable = VARIABLE_NAMES.iter().any(|name| token.contains(name));
        // The accessor takes no arguments. Any identifier ending in its name
        // and called with none counts, as it did under the text match; one
        // called with arguments counts only if it is the accessor's own name,
        // which keeps `without_launch_nonce(&mut command)`, the helper that
        // strips the nonce from a child, from reading as a read.
        let calls_accessor = token_at(index + 1) == Some("(")
            && (token == ACCESSOR
                || (token.ends_with(ACCESSOR) && token_at(index + 2) == Some(")")));
        let references_accessor = token == ACCESSOR
            && (token_at(index + 1) == Some("as")
                || (index >= 2
                    && token_at(index - 2) == Some("subc_os")
                    && token_at(index - 1) == Some("::")));
        let is_mention = names_variable || calls_accessor || references_accessor;
        if is_mention && found.last().is_none_or(|(last, _)| *last != line_number) {
            found.push((line_number, lines[line_number - 1].1));
        }
    }
    found
}

/// A file outside the reader and the allowed list, for planted source.
const ELSEWHERE: &str = "crates/cerebellum/src/consent.rs";

/// One planted read per variable spelling and the accessor, through
/// `std::env::var`, `std::env::var_os` and the accessor's call.
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
/// blind alike, so on its own a green result proves nothing. Every spelling the
/// detector looks for is planted, so dropping or breaking one fails here.
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
    // Layout variants. The plain-text match this detector replaced caught the
    // variable forms on the line holding the name, as this does, but missed
    // the accessor spaced from its parentheses, split between them, renamed on
    // import, or taken as a value. Each form is kept here so that a return to
    // text matching fails by name.
    let variants: &[(&str, &[&str], &[usize])] = &[
        (
            "the variable name on the line after env::var(",
            &[
                "let nonce = std::env::var(",
                "    \"SUBC_LAUNCH_NONCE\",",
                ");",
            ],
            &[2],
        ),
        (
            "the variable name held in a const",
            &[
                "const NAME: &str = \"SUBC_LAUNCH_NONCE\";",
                "fn hello() { let nonce = std::env::var(NAME); }",
            ],
            &[1],
        ),
        (
            "the subc_os constant split from its path",
            &[
                "let fd = std::env::var_os(subc_os::",
                "    LAUNCH_NONCE_FD_ENV);",
            ],
            &[2],
        ),
        (
            "a space before the accessor's parentheses",
            &["let nonce = subc_os::launch_nonce ();"],
            &[1],
        ),
        (
            "the accessor's call split across lines",
            &["let nonce = subc_os::launch_nonce(", ");"],
            &[1],
        ),
        (
            "the accessor's path split across lines",
            &["let nonce = subc_os::", "    launch_nonce();"],
            &[2],
        ),
        (
            "the accessor imported under another name",
            &[
                "use subc_os::launch_nonce as read_proof;",
                "fn hello() { let nonce = read_proof(); }",
            ],
            &[1],
        ),
        (
            "the accessor imported in a group and renamed",
            &[
                "use subc_os::{",
                "    launch_nonce as read_proof,",
                "    ModuleIdentity,",
                "};",
            ],
            &[2],
        ),
        (
            "the accessor taken as a function value",
            &["let read = subc_os::launch_nonce;"],
            &[1],
        ),
    ];
    for (case, lines, expected) in variants {
        assert_flags(case, ELSEWHERE, &lines.join("\n"), expected);
    }

    // Test markers of every shape. This scan has no notion of test code, so
    // a marker never hides anything: the read in the marked item and the one
    // in shipped code after it are both flagged, whatever the marker is on,
    // whether it is real code or sits in a comment or string, and whatever
    // its predicate (`all(test, ..)`, `any(test, ..)`).
    let marked: &[(&str, &[&str], &[usize])] = &[
        (
            "a marked fn, then a shipped module",
            &[
                "#[cfg(test)]",
                "fn helper() { let nonce = std::env::var(\"SUBC_LAUNCH_NONCE\"); }",
                "mod shipped {",
                "    fn open() { let nonce = subc_os::launch_nonce(); }",
                "}",
            ],
            &[2, 4],
        ),
        (
            "a marked const",
            &[
                "#[cfg(test)]",
                "const NAME: &str = \"SUBC_LAUNCH_NONCE\";",
                "fn open() { let fd = std::env::var_os(subc_os::LAUNCH_NONCE_FD_ENV); }",
            ],
            &[2, 3],
        ),
        (
            "a marked use",
            &[
                "#[cfg(test)]",
                "use subc_os::LAUNCH_NONCE_ENV;",
                "fn open() { let nonce = subc_os::launch_nonce(); }",
            ],
            &[2, 3],
        ),
        (
            "a marked impl",
            &[
                "#[cfg(test)]",
                "impl Probe {",
                "    fn read() { let nonce = subc_os::launch_nonce(); }",
                "}",
                "impl Probe {",
                "    fn open() { let nonce = std::env::var(subc_os::LAUNCH_NONCE_ENV); }",
                "}",
            ],
            &[3, 6],
        ),
        (
            "a marker in a comment",
            &[
                "// #[cfg(test)]",
                "mod shipped {",
                "    fn open() { let nonce = subc_os::launch_nonce(); }",
                "}",
            ],
            &[3],
        ),
        (
            "a marker in a string literal",
            &[
                "const EXAMPLE: &str = \"",
                "#[cfg(test)]",
                "mod tests {\";",
                "fn open() { let nonce = subc_os::launch_nonce(); }",
            ],
            &[4],
        ),
        (
            "a cfg(all(test, ..)) module",
            &[
                "#[cfg(all(test, feature = \"live\"))]",
                "mod live_tests {",
                "    fn read() { let nonce = subc_os::launch_nonce(); }",
                "}",
            ],
            &[3],
        ),
        (
            "a cfg(any(test, ..)) module",
            &[
                "#[cfg(any(test, feature = \"fixtures\"))]",
                "mod fixtures {",
                "    fn read() { let nonce = subc_os::launch_nonce(); }",
                "}",
            ],
            &[3],
        ),
    ];
    for (case, lines, expected) in marked {
        assert_flags(case, ELSEWHERE, &lines.join("\n"), expected);
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
    // one sharing the prefix, the reader module and paths through it, and
    // names that only contain the accessor's.
    assert_flags(
        "code that does not touch the nonce",
        ELSEWHERE,
        &[
            "mod launch_nonce;",
            "use crate::launch_nonce;",
            "fn hello() {",
            "    let home = std::env::var(\"HOME\");",
            "    let id = std::env::var_os(\"SUBC_LAUNCH_ID\");",
            "    launch_nonce::scrub_child_environment(&mut command);",
            "    crate::launch_nonce::verify(&proof);",
            "    crate::launch_nonce::without_launch_nonce(&mut command);",
            "    let proof = handoff.nonce();",
            "    let source = provenance.launch_nonce_source;",
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
    assert!(
        scan.unused_allowances.is_empty(),
        "the copied tree still holds every allowed mention, so the walk must find them: {:?}",
        scan.unused_allowances
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
