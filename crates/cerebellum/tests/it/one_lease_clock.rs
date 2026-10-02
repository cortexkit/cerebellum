//! The module keeps one lease clock, and the compiler cannot say so.
//!
//! `SystemClock`'s epoch is fixed per instance, so two of them are not
//! comparable even though both produce a `MonoInstant`. A lease stamped by one
//! reads as long expired to the other, and the types agree at every step.
//!
//! That is not hypothetical here. Two consent sites built a fresh clock instead
//! of using the module's shared one: the ask settlement that MINTS a lease, and
//! `computer.open_target` itself. The result on a running module was that
//! `open_target` answered `already_held` with ten minutes remaining while every
//! computer action refused `no_lease` -- a remedy loop, since the refusal's
//! remedy was the call that had just succeeded. It stayed invisible while the module's
//! uptime was under the grant window and was total past it, which is why every
//! live probe had passed: each one ran minutes after a restart.
//!
//! A behavioural fence cannot reach this: reproducing it needs a module whose
//! uptime already exceeds a lease, and a freshly built `Planes` is always zero
//! seconds old. So the fence is structural -- exactly one construction site on
//! the production paths, the one that builds the module's own clock.

use std::path::{Path, PathBuf};

/// Construction sites allowed outside test code: the file, the site's exact
/// trimmed line, and the reason it exists. The line is matched exactly so that
/// the real-tree scan can insist on finding it: a site that is renamed or moved
/// fails the scan instead of leaving it to pass over nothing.
const ALLOWED: &[(&str, &str, &str)] = &[(
    "src/lib.rs",
    "let lease_clock = Arc::new(cerebellum_core::clock::SystemClock::new());",
    "the module's own lease clock, built once in Planes::new and shared by Arc",
)];

/// The fewest `.rs` files the real-tree walk may read and still pass. The crate
/// had 66 under `src` when this was set; the floor sits well below that so
/// ordinary churn never trips it, while a walk pointed at the wrong root, or
/// one that stopped descending, falls under it even if it still reaches the
/// file holding the allowed site.
const MIN_FILES_SCANNED: usize = 40;

#[test]
fn only_the_module_lease_clock_is_constructed_on_production_paths() {
    let scan = scan_crate(Path::new(env!("CARGO_MANIFEST_DIR")));

    assert!(
        scan.files_scanned >= MIN_FILES_SCANNED,
        "the scan read {} files under src, below the floor of {MIN_FILES_SCANNED}, \
         so it is not looking at the whole crate and a clean result proves nothing",
        scan.files_scanned
    );
    // The module's own clock has to be built somewhere, so not finding it means
    // the scan has gone blind or the site moved without this list following.
    assert!(
        scan.missing_allowed.is_empty(),
        "the allowed construction site was not found, so a clean result would \
         prove nothing. If it moved or was reworded on purpose, update ALLOWED:\n{}",
        scan.missing_allowed.join("\n")
    );
    // One message for both shapes, because the remedy is the same whether the
    // extra clock appeared in a new file or beside the allowed one.
    assert!(
        scan.violations.is_empty(),
        "a second clock cannot share the first one's epoch, so a lease it stamps \
         reads as expired everywhere else. Take the module's clock from \
         planes.lease_clock instead of building one here.\nallowed:\n{}\nfound:\n{}",
        ALLOWED
            .iter()
            .map(|(path, line, reason)| format!("  {path}: {line} ({reason})"))
            .collect::<Vec<_>>()
            .join("\n"),
        scan.violations
            .iter()
            .map(|site| format!("  {site}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// What one walk over a crate's `src` found.
struct TreeScan {
    files_scanned: usize,
    /// Allowed sites, as `path: line`, that the walk did not find.
    missing_allowed: Vec<String>,
    /// Forbidden construction sites, as `path:line: text`.
    violations: Vec<String>,
}

/// Walks every `.rs` file under `crate_root/src` and runs the detector on each,
/// with paths reported relative to `crate_root`.
fn scan_crate(crate_root: &Path) -> TreeScan {
    let mut scan = TreeScan {
        files_scanned: 0,
        missing_allowed: Vec::new(),
        violations: Vec::new(),
    };
    let mut allowed_found = vec![false; ALLOWED.len()];
    for file in rust_sources(&crate_root.join("src")) {
        scan.files_scanned += 1;
        let relative = file
            .strip_prefix(crate_root)
            .expect("sources live under the crate root")
            .to_string_lossy()
            .replace('\\', "/");
        let source = std::fs::read_to_string(&file).expect("read a crate source file");
        let sites = construction_sites(&source);
        for (found, (path, line, _)) in allowed_found.iter_mut().zip(ALLOWED) {
            if *path == relative && sites.iter().any(|(_, text)| text == line) {
                *found = true;
            }
        }
        scan.violations.extend(clock_violations(&relative, &source));
    }
    for (found, (path, line, _)) in allowed_found.iter().zip(ALLOWED) {
        if !found {
            scan.missing_allowed.push(format!("{path}: {line}"));
        }
    }
    scan
}

/// The clock construction sites in one file that the fence forbids, each as
/// `path:line: text`.
///
/// Each [`ALLOWED`] entry for this file excuses one production site whose line
/// matches it exactly; every other site is a violation, including a second
/// copy of the allowed line. Sites inside `#[cfg(test)]` modules are never
/// counted.
fn clock_violations(path: &str, source: &str) -> Vec<String> {
    let mut allowances: Vec<&str> = ALLOWED
        .iter()
        .filter(|(allowed_path, _, _)| *allowed_path == path)
        .map(|(_, line, _)| *line)
        .collect();
    let mut violations = Vec::new();
    for (line_number, text) in construction_sites(source) {
        if let Some(index) = allowances.iter().position(|line| *line == text) {
            allowances.remove(index);
        } else {
            violations.push(format!("{path}:{line_number}: {text}"));
        }
    }
    violations
}

/// Every production line that builds a `SystemClock`, with its 1-based number
/// and trimmed text.
///
/// The match is plain text on the line, so a mention in a comment or a string
/// literal counts as a construction too. The effect is that the fence errs
/// towards a false alarm the author can reword, never towards a missed clock.
fn construction_sites(source: &str) -> Vec<(usize, String)> {
    production_lines(source)
        .into_iter()
        .filter(|(_, line)| {
            line.contains("SystemClock::new()") || line.contains("SystemClock::default()")
        })
        .map(|(line_number, line)| (line_number, line.trim().to_string()))
        .collect()
}

/// Every `.rs` file under a directory, recursively.
fn rust_sources(directory: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![directory.to_path_buf()];
    while let Some(next) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path);
            }
        }
    }
    files
}

/// Lines outside every `#[cfg(test)]` module, with their 1-based numbers.
///
/// Test code builds its own clocks deliberately and that is fine: a test owns
/// the whole timeline it measures. Skipping by brace balance rather than by
/// "everything after the first test module", because this crate's largest file
/// carries production code after one test module and before the next.
fn production_lines(source: &str) -> Vec<(usize, &str)> {
    let mut kept = Vec::new();
    let mut skipping_from_depth: Option<i32> = None;
    let mut depth = 0_i32;
    let mut pending_test_module = false;
    for (index, line) in source.lines().enumerate() {
        let opens = line.matches('{').count() as i32;
        let closes = line.matches('}').count() as i32;
        if skipping_from_depth.is_none() {
            if pending_test_module && line.contains("mod ") && line.contains('{') {
                skipping_from_depth = Some(depth);
                pending_test_module = false;
                depth += opens - closes;
                continue;
            }
            if line.trim_start().starts_with("#[cfg(test)]") {
                pending_test_module = true;
                depth += opens - closes;
                continue;
            }
            kept.push((index + 1, line));
        }
        depth += opens - closes;
        if let Some(entered_at) = skipping_from_depth {
            if depth <= entered_at {
                skipping_from_depth = None;
            }
        }
    }
    kept
}

/// The fence's positive control: planted constructions the detector must flag.
///
/// The real-tree test passes on a clean tree and on a detector that has gone
/// blind alike, so on its own a green result proves nothing. These cases fail
/// if the matching, the allowance or the `#[cfg(test)]` skipping stops finding
/// what it should.
#[test]
fn the_clock_detector_flags_every_planted_construction() {
    assert_flags(
        "a second SystemClock::new() beside the allowed one",
        "src/lib.rs",
        &[
            "fn planes_new() {",
            "    let lease_clock = Arc::new(cerebellum_core::clock::SystemClock::new());",
            "}",
            "fn consent() {",
            "    let clock = SystemClock::new();",
            "}",
        ],
        &[5],
    );
    // The allowance is for one site, so the allowed line written twice is a
    // second clock all the same.
    assert_flags(
        "the allowed line repeated in the allowed file",
        "src/lib.rs",
        &[
            "let lease_clock = Arc::new(cerebellum_core::clock::SystemClock::new());",
            "let lease_clock = Arc::new(cerebellum_core::clock::SystemClock::new());",
        ],
        &[2],
    );
    assert_flags(
        "the allowed line in a file with no allowance",
        "src/consent.rs",
        &["let lease_clock = Arc::new(cerebellum_core::clock::SystemClock::new());"],
        &[1],
    );
    assert_flags(
        "SystemClock::new() in a file with no allowance",
        "src/consent.rs",
        &["fn open() {", "    let clock = SystemClock::new();", "}"],
        &[2],
    );
    assert_flags(
        "SystemClock::default()",
        "src/consent.rs",
        &[
            "fn open() {",
            "    let clock = SystemClock::default();",
            "}",
        ],
        &[2],
    );
    // The shape of lib.rs: production code between two test modules. Only the
    // production site is flagged, and the second module is still skipped.
    assert_flags(
        "production code after a test module",
        "src/consent.rs",
        &[
            "#[cfg(test)]",
            "mod first_tests {",
            "    fn helper() {",
            "        let clock = SystemClock::new();",
            "    }",
            "}",
            "",
            "fn after_the_tests() {",
            "    let clock = SystemClock::new();",
            "}",
            "",
            "#[cfg(test)]",
            "mod second_tests {",
            "    fn helper() {",
            "        let clock = SystemClock::default();",
            "    }",
            "}",
        ],
        &[9],
    );
    // Neither of these builds a clock, but the scanner matches text on the line
    // and does not parse comments or strings, so both count. Pinned so that
    // changing that is a decision someone makes here, not a side effect.
    assert_flags(
        "a commented-out construction",
        "src/consent.rs",
        &["fn open() {", "    // let clock = SystemClock::new();", "}"],
        &[2],
    );
    assert_flags(
        "a construction named in a string literal",
        "src/consent.rs",
        &[
            "fn open() {",
            "    let hint = \"use planes.lease_clock, not SystemClock::default()\";",
            "}",
        ],
        &[2],
    );
}

/// The fence's negative control: planted source the detector must pass.
///
/// A detector that flags too much, such as every mention of the type or every
/// test module, tends to get loosened by hand until the tree passes. These
/// cases pin what is not a violation, so over-matching fails here by name.
#[test]
fn the_clock_detector_passes_every_planted_non_construction() {
    assert_flags(
        "the allowed site in the allowed file",
        "src/lib.rs",
        &[
            "fn planes_new() {",
            "    let lease_clock = Arc::new(cerebellum_core::clock::SystemClock::new());",
            "}",
        ],
        &[],
    );
    assert_flags(
        "a site inside a #[cfg(test)] module",
        "src/consent.rs",
        &[
            "#[cfg(test)]",
            "mod tests {",
            "    fn helper() {",
            "        let clock = SystemClock::new();",
            "        let other = SystemClock::default();",
            "    }",
            "}",
        ],
        &[],
    );
    assert_flags(
        "code that names the clock type or uses the shared clock",
        "src/consent.rs",
        &[
            "use cerebellum_core::clock::SystemClock;",
            "fn with_clock(clock: Arc<SystemClock>) -> Self {",
            "    let shared = Arc::clone(&planes.lease_clock);",
            "    let fake = MockClock::new();",
            "    let now = shared.now();",
            "}",
        ],
        &[],
    );
}

/// The walk's control: the real-tree scan's own walk, run over a copy of this
/// crate's `src` with one violating file planted two directories down.
///
/// The snippet controls exercise the detector on text handed to it, and the
/// premise check only proves the walk reaches `src/lib.rs`. Neither notices a
/// walk that stops descending into module directories or reads the wrong file
/// extension; this does.
#[test]
fn the_tree_walk_reports_a_planted_file_in_a_nested_module() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let scratch = scratch_directory("lease-clock-walk");
    copy_tree(&crate_root.join("src"), &scratch.join("src"));
    let nested = scratch.join("src/planted/deeper");
    std::fs::create_dir_all(&nested).expect("create the planted module directory");
    let planted = "pub fn second() { let _ = SystemClock::new(); }\n";
    std::fs::write(nested.join("second_clock.rs"), planted).expect("plant the violation");
    // The same text in a file that is not Rust source must not be read.
    std::fs::write(nested.join("second_clock.txt"), planted).expect("plant the decoy");

    let scan = scan_crate(&scratch);
    let _ = std::fs::remove_dir_all(&scratch);

    assert_eq!(
        scan.violations,
        ["src/planted/deeper/second_clock.rs:1: pub fn second() { let _ = SystemClock::new(); }"],
        "the walk must report the planted .rs file by path, and only it"
    );
    assert!(
        scan.missing_allowed.is_empty(),
        "the copied tree still holds the allowed site, so the walk must find it: {:?}",
        scan.missing_allowed
    );
}

/// Runs the detector over planted lines and asserts exactly `expected` (1-based
/// line numbers) are flagged.
fn assert_flags(case: &str, path: &str, lines: &[&str], expected: &[usize]) {
    let violations = clock_violations(path, &lines.join("\n"));
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
