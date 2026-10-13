//! No trace of the reverse elicitation lane is left.
//!
//! Cerebellum used to put a permission question to a person by sending an
//! `elicitation/create` request back along the route of the agent's own call,
//! answered by whoever held that route. Every card is now raised with
//! Cingulate, the consent module, over a route cerebellum opens itself, and
//! the lane is gone with no fallback. These scans keep it gone: a test that
//! still answers on the lane, or shipped code that still sends on it, would
//! otherwise compile and pass while describing a path nothing serves.

use std::path::{Path, PathBuf};

use crate::support::source_scan;

/// Identifiers only the removed path used: the type that sent a question
/// back on the agent's route and the type of its outcome, the queue of
/// outstanding questions beneath it, the answer word a relaying client sent
/// for silence, and the route-bind fact that said the client could relay a
/// question to a person.
const LANE_NAMES: &[&str] = &[
    "Elicitor",
    "ask_for_call",
    "AskLane",
    "AskOutcome",
    "NO_ANSWER_DECISION",
    "declares_elicitation",
];

/// The method of the request the lane sent. Shipped code that names it in
/// code or in a string is building that request; a doc comment may still
/// describe the lane's history.
const LANE_METHOD: &str = "elicitation/create";

fn crates_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate lives in the workspace's crates directory")
        .to_path_buf()
}

/// Every file under `root`, except build output and the copied consent
/// vectors, which are Cingulate's own bytes and are not edited here.
fn files_under(root: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        panic!("could not list {}", root.display());
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let skipped = path.file_name().is_some_and(|name| name == "target")
                || path.ends_with("tests/vectors");
            if !skipped {
                files_under(&path, found);
            }
        } else {
            found.push(path);
        }
    }
}

/// The lane names `text` mentions.
fn lane_names(text: &str) -> Vec<&'static str> {
    LANE_NAMES
        .iter()
        .copied()
        .filter(|name| text.contains(name))
        .collect()
}

/// The lines of shipped Rust `source` that name the lane's method outside a
/// comment, with their numbers. Test-only items are set aside first.
fn lane_sends(source: &str) -> Vec<(usize, String)> {
    source_scan::shipped_lines(source)
        .into_iter()
        .filter(|(_, line)| {
            let code = line.trim_start();
            !code.starts_with("//") && code.contains(LANE_METHOD)
        })
        .collect()
}

#[test]
fn no_file_names_the_reverse_lane() {
    let crates = crates_root();
    let this_file = crates.join("cerebellum/tests/it/no_reverse_lane.rs");
    let mut files = Vec::new();
    for member in ["cerebellum", "cerebellum-core"] {
        files_under(&crates.join(member), &mut files);
    }
    let mut found = Vec::new();
    let mut scanned = 0;
    for file in files.iter().filter(|file| **file != this_file) {
        // Binary fixtures hold no source text to name anything.
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        scanned += 1;
        for name in lane_names(&text) {
            found.push(format!("{}: {name}", file.display()));
        }
    }
    // Both crates hold hundreds of files, so a small count means the walk
    // looked in the wrong place and proved nothing.
    assert!(
        scanned > 200,
        "the scan read only {scanned} files, so it proved nothing"
    );
    assert!(
        found.is_empty(),
        "the reverse lane is named again:\n{}",
        found.join("\n")
    );

    // Each name is seen when planted in a real scanned file.
    let lib = std::fs::read_to_string(crates.join("cerebellum/src/lib.rs")).unwrap();
    assert!(lane_names(&lib).is_empty());
    for name in LANE_NAMES {
        let planted = lib.replace("pub mod wire;", &format!("pub mod wire;\nuse {name};"));
        assert_eq!(lane_names(&planted), [*name], "planted {name} was not seen");
    }
}

#[test]
fn shipped_code_sends_no_reverse_lane_question() {
    let crates = crates_root();
    let mut found = Vec::new();
    let mut scanned = 0;
    for member in ["cerebellum", "cerebellum-core"] {
        let mut files = Vec::new();
        files_under(&crates.join(member).join("src"), &mut files);
        files.retain(|file| file.extension().is_some_and(|ext| ext == "rs"));
        // Files an out-of-line test module loads are test code throughout.
        let test_files = source_scan::test_only_module_files(&files);
        for file in files.iter().filter(|file| !test_files.contains(file)) {
            scanned += 1;
            let source = std::fs::read_to_string(file).expect("read a source file");
            for (line_number, line) in lane_sends(&source) {
                found.push(format!("{}:{line_number}: {}", file.display(), line.trim()));
            }
        }
    }
    assert!(
        scanned > 100,
        "the scan read only {scanned} sources, so it proved nothing"
    );
    assert!(
        found.is_empty(),
        "shipped code builds a reverse-lane question:\n{}",
        found.join("\n")
    );

    // Planted in the card renderer, a lane request body is seen; the same
    // text in a doc comment or in a test-only item is not.
    let card = std::fs::read_to_string(crates.join("cerebellum/src/consent_card.rs")).unwrap();
    let anchor = r#"json!({ "params": params })"#;
    assert!(card.contains(anchor), "the planted control lost its anchor");
    assert!(lane_sends(&card).is_empty());
    let planted = card.replace(
        anchor,
        r#"json!({"method": "elicitation/create", "params": params})"#,
    );
    assert_eq!(
        lane_sends(&planted).len(),
        1,
        "a planted lane send was not seen"
    );
    let documented = card.replace(
        "pub(crate) struct ConsentCard {",
        "/// Once sent as `elicitation/create`.\npub(crate) struct ConsentCard {",
    );
    assert!(lane_sends(&documented).is_empty());
    let tested = format!(
        "{card}\n#[cfg(test)]\nmod planted {{\n    const M: &str = \"elicitation/create\";\n}}\n"
    );
    assert!(lane_sends(&tested).is_empty());
}
