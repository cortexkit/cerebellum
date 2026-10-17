//! Durable data stores must use the owner-only filesystem primitives.
use std::path::Path;

use crate::support::source_scan;

const STORE_FILES: &[&str] = &[
    "crates/cerebellum-core/src/format_floor.rs",
    "crates/cerebellum-core/src/engram_catalog.rs",
    "crates/cerebellum-core/src/journal/storage.rs",
    "crates/cerebellum-core/src/journal/refusal_ring.rs",
    "crates/cerebellum/src/computer_grants.rs",
    "crates/cerebellum/src/browser_standing_grants.rs",
    "crates/cerebellum/src/journal/call_records.rs",
    "crates/cerebellum/src/profile_custody/holder_lock.rs",
];

#[test]
fn durable_store_modules_do_not_create_files_directly() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let mut scanned = 0;
    let mut violations = Vec::new();
    for relative in STORE_FILES {
        let path = workspace.join(relative);
        let source = std::fs::read_to_string(&path).expect("read durable store source");
        scanned += 1;
        for (line, violation) in direct_write_violations(&source) {
            violations.push(format!("{relative}:{line}: {violation}"));
        }
    }
    assert_eq!(
        scanned,
        STORE_FILES.len(),
        "scan must cover every named store"
    );
    assert!(
        violations.is_empty(),
        "direct durable writes found:\n{}",
        violations.join("\n")
    );
}

fn direct_write_violations(source: &str) -> Vec<(usize, String)> {
    const FORBIDDEN: &[&str] = &[
        "File::create(",
        "fs::write(",
        "std::fs::write(",
        ".create_new(true)",
    ];
    let code = source_scan::shipped_code(source);
    code.lines()
        .enumerate()
        .filter_map(|(index, line)| {
            FORBIDDEN
                .iter()
                .find(|form| line.contains(**form))
                .map(|form| (index + 1, (*form).to_string()))
        })
        .collect()
}

fn function_body<'a>(code: &'a str, signature: &str) -> &'a str {
    let start = code.find(signature).expect("function signature exists");
    let body_start = start + code[start..].find('{').expect("function body starts") + 1;
    let mut depth = 1usize;
    for (offset, character) in code[body_start..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &code[body_start..body_start + offset];
                }
            }
            _ => {}
        }
    }
    panic!("function body is not closed")
}

#[test]
fn source_scan_detects_every_forbidden_write_form() {
    for form in [
        "File::create(",
        "fs::write(",
        "std::fs::write(",
        ".create_new(true)",
    ] {
        let source = format!("fn production() {{ let _ = {form}value); }}");
        assert_eq!(
            direct_write_violations(&source).len(),
            1,
            "scanner missed {form}"
        );
    }
}

#[test]
fn source_scan_ignores_comments_literals_and_test_only_modules() {
    let source = r#"
// File::create( fs::write( std::fs::write( .create_new(true)
const EXAMPLE: &str = "File::create( fs::write( std::fs::write( .create_new(true)";
#[cfg(test)]
mod tests {
    fn fixture() { File::create(x); fs::write(x, y); std::fs::write(x, y); options.create_new(true); }
}
"#;
    assert!(direct_write_violations(source).is_empty());
}

#[test]
fn prepared_test_entry_does_not_tighten_operator_state() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let source = std::fs::read_to_string(workspace.join("crates/cerebellum/src/lib.rs"))
        .expect("read production entry points");
    let code = source_scan::shipped_code(&source);
    let prepared = function_body(&code, "pub async fn run_entry_prepared_for_test");
    assert!(
        !prepared.contains("record_private_state_tightening"),
        "prepared test entry must not tighten the operator's live state"
    );
    let production = function_body(&code, "pub async fn run_entry()");
    assert!(
        production.contains("record_private_state_tightening"),
        "production entry must tighten state before running"
    );
}

/// The backup catalog is written into the data home that `XDG_DATA_HOME` and
/// `HOME` resolve to, which during a test run is the operator's own. So only
/// the production entry point may write it; the entry child-process tests run
/// must not, or every test run would rewrite the operator's live catalog.
#[test]
fn prepared_test_entry_does_not_write_the_engram_catalog() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let source = std::fs::read_to_string(workspace.join("crates/cerebellum/src/lib.rs"))
        .expect("read production entry points");
    let code = source_scan::shipped_code(&source);
    let prepared = function_body(&code, "pub async fn run_entry_prepared_for_test");
    assert!(
        !prepared.contains("record_engram_catalog_write"),
        "prepared test entry must not write the operator's backup catalog"
    );
    let production = function_body(&code, "pub async fn run_entry()");
    assert!(
        production.contains("record_engram_catalog_write"),
        "production entry must write the backup catalog at startup"
    );
    // The catalog writer is reached from the production entry point and
    // nowhere else in shipped code.
    assert_eq!(
        code.matches("record_engram_catalog_write()").count(),
        2,
        "expected exactly the definition and the production call"
    );
}
