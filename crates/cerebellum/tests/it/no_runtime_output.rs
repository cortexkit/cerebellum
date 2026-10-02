//! Shipped code writes nothing to standard output or standard error.
//!
//! The daemon captures a module's standard streams into a file under the
//! backed-up data home, and that file's size staying constant is how the fleet
//! checks that no shipped path prints. A print on a rare path -- a failed
//! delete, a missing listener -- passes every test and grows that file only on
//! the machine where the rare thing happens. So the fence is structural: no
//! print macro outside test code, in any crate of this workspace, except the
//! ones listed below with their reason.

use std::path::{Path, PathBuf};

use crate::support::source_scan;

/// The print macros looked for. `print!(` also finds `eprint!(`.
const PRINT_MACROS: &[&str] = &["println!(", "print!(", "dbg!("];

/// Prints allowed outside test code, as (path from the workspace root, the
/// text of the line, the reason).
const ALLOWED: &[(&str, &str, &str)] = &[(
    "crates/cerebellum/src/main.rs",
    "println!(",
    "`--version`, the one output the module ships; it runs before the module \
         starts and is read by the person who asked for it",
)];

#[test]
fn shipped_code_prints_nothing() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate lives in the workspace's crates directory");
    let workspace = crates.parent().expect("crates sits in the workspace root");
    let mut found = Vec::new();
    let mut files_scanned = 0;
    let Ok(members) = std::fs::read_dir(crates) else {
        panic!("could not list {}", crates.display());
    };
    for member in members.flatten() {
        // Files an out-of-line test module loads are test code throughout.
        let files = rust_sources(&member.path().join("src"));
        let test_files = source_scan::test_only_module_files(&files);
        for file in files.iter().filter(|file| !test_files.contains(file)) {
            files_scanned += 1;
            let relative = file
                .strip_prefix(workspace)
                .expect("sources live under the workspace root")
                .to_string_lossy()
                .replace('\\', "/");
            let source = std::fs::read_to_string(&file).expect("read a source file");
            for (line_number, line) in source_scan::shipped_lines(&source) {
                let code = line.trim_start();
                if code.starts_with("//") {
                    continue;
                }
                if PRINT_MACROS.iter().any(|name| code.contains(name)) {
                    found.push((relative.clone(), line_number, code.to_string()));
                }
            }
        }
    }

    // Every crate has sources, so a small count means the scan looked in the
    // wrong place and proved nothing.
    assert!(
        files_scanned > 20,
        "the scan found only {files_scanned} sources, so it proved nothing"
    );
    // An exception whose print is gone must leave the list, or the list stops
    // describing the code and the next print could hide behind a stale entry.
    for (path, text, _) in ALLOWED {
        assert!(
            found
                .iter()
                .any(|(found_path, _, code)| found_path == path && code.starts_with(text)),
            "{path} no longer has the allowed print `{text}`; remove it from ALLOWED"
        );
    }
    let unexpected: Vec<_> = found
        .iter()
        .filter(|(path, _, code)| {
            !ALLOWED
                .iter()
                .any(|(allowed, text, _)| allowed == path && code.starts_with(text))
        })
        .collect();
    assert!(
        unexpected.is_empty(),
        "shipped code must not print: the daemon keeps the module's standard streams \
         in a backed-up file whose size is how printing is detected. Record the event \
         where a person can read it instead (a reply, or the health reply's metrics).\n{}",
        unexpected
            .iter()
            .map(|(path, line, code)| format!("  {path}:{line}: {code}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Every `.rs` file under a directory, recursively.
fn rust_sources(directory: &Path) -> Vec<PathBuf> {
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

/// Test code prints freely; only shipped code is fenced. This checks the scan
/// sees that the shared skipper sets test items aside, and keeps the
/// production prints around them.
#[test]
fn the_scan_skips_test_items_and_keeps_production_lines() {
    let source = "fn a() { eprintln!(\"a\"); }\n\
                  #[cfg(test)]\n\
                  mod tests {\n\
                  fn t() { println!(\"t\"); }\n\
                  }\n\
                  #[cfg(all(test, target_os = \"macos\"))]\n\
                  #[test]\n\
                  fn only_in_tests(\n\
                  ) {\n\
                  dbg!(1);\n\
                  }\n\
                  #[cfg(test)]\n\
                  mod elsewhere;\n\
                  fn b() {\n\
                  print!(\"b\");\n\
                  }\n";
    let kept: Vec<_> = source_scan::shipped_lines(source)
        .into_iter()
        .filter(|(_, line)| PRINT_MACROS.iter().any(|name| line.contains(name)))
        .collect();

    assert_eq!(
        kept.iter().map(|(number, _)| *number).collect::<Vec<_>>(),
        [1, 15],
        "the scan must keep both production prints and drop the three in test code: {kept:?}"
    );
}
