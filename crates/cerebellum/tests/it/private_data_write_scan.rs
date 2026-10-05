//! Durable data stores must use the owner-only filesystem primitives.
use std::path::Path;

use crate::support::source_scan;

const STORE_FILES: &[&str] = &[
    "crates/cerebellum-core/src/format_floor.rs",
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
        for (line, code) in source_scan::shipped_lines(&source) {
            let code = code.trim_start();
            if code.contains("File::create(")
                || code.contains("fs::write(")
                || code.contains("std::fs::write(")
                || code.contains(".create_new(true)")
            {
                violations.push(format!("{relative}:{line}: {code}"));
            }
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
