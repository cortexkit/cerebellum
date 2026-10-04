//! Every outcome word a browser.launch path can reply with is declared.
//!
//! The browser control replies pass a closed result schema before they reach
//! the wire, and a reply the schema does not declare is withheld: the caller
//! receives `computer_result_schema_violation` instead of the refusal, with its
//! reason and remedy gone. That is how a real launch refused by an untrusted
//! profile root reached its caller as a schema violation that said nothing.
//!
//! The typed renderers are checked variant by variant in their own modules.
//! This fence covers what those cannot see: an `"outcome": "<word>"` literal
//! written straight into a `json!` on a launch path. It also refuses a
//! string-valued `detail`, because the schemas declare `detail` as the
//! invalid-request object, and a free-text one gets the whole reply withheld
//! while carrying internal state (paths, profile directories) to the wire.

use std::path::Path;

use serde_json::json;

use crate::support::source_scan;

/// Production sources that build browser.launch, status, or close replies.
const LAUNCH_PATH_FILES: &[&str] = &[
    "src/browser_launch.rs",
    "src/browser_launch_service.rs",
    "src/browser_launch_readiness.rs",
    "src/browser_executable_identity.rs",
    "src/browser_session.rs",
];

/// `lib.rs` serves every plane, so only the browser control handler is read.
const LIB_FUNCTION: (&str, &str) = ("src/lib.rs", "async fn handle_browser_control(");

/// Fewer distinct words than this means the scan stopped reading the sources
/// it names, and an empty scan proves nothing.
const MINIMUM_DISTINCT_WORDS: usize = 21;

#[test]
fn every_launch_path_outcome_literal_is_declared_by_a_browser_session_schema() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = Vec::new();
    for relative in LAUNCH_PATH_FILES {
        let text = std::fs::read_to_string(crate_root.join(relative))
            .unwrap_or_else(|error| panic!("read {relative}: {error}"));
        // Test modules write refusal fixtures of their own, including
        // deliberately undeclared ones; only what production can send is
        // fenced.
        sources.push((relative.to_string(), source_scan::shipped_lines(&text)));
    }
    let (lib_path, lib_function) = LIB_FUNCTION;
    let lib = std::fs::read_to_string(crate_root.join(lib_path)).expect("read src/lib.rs");
    let handler = function_lines(&lib, lib_function);
    assert!(
        !handler.is_empty(),
        "{lib_function} was not found in {lib_path}; update the fence"
    );
    sources.push((lib_path.to_string(), handler));

    let mut words = std::collections::BTreeMap::<String, Vec<String>>::new();
    let mut string_details = Vec::new();
    for (path, lines) in &sources {
        for (number, line) in lines {
            for word in outcome_words(line) {
                words
                    .entry(word)
                    .or_default()
                    .push(format!("{path}:{number}"));
            }
            if has_string_detail(line) {
                string_details.push(format!("{path}:{number}: {}", line.trim()));
            }
        }
    }

    assert!(
        words.len() > MINIMUM_DISTINCT_WORDS,
        "the scan found only {} distinct outcome words, so it is not reading the \
         launch path: {:?}",
        words.len(),
        words.keys().collect::<Vec<_>>()
    );

    let undeclared: Vec<String> = words
        .iter()
        .filter(|(word, _)| !declared_by_a_session_schema(word))
        .map(|(word, sites)| format!("  {word}: {}", sites.join(", ")))
        .collect();
    assert!(
        undeclared.is_empty(),
        "these outcome words are written on a browser control path but no \
         browser.launch/status/close schema declares them, so the reply is \
         withheld as a schema violation. Declare each in crates/cerebellum/src/\
         browser/mod.rs with every key it carries:\n{}",
        undeclared.join("\n")
    );
    assert!(
        string_details.is_empty(),
        "a string `detail` on a browser control reply violates the declared \
         invalid-request object and puts internal state on the wire. Drop it, \
         or carry the distinction as a declared reason_code:\n{}",
        string_details.join("\n")
    );
}

/// A word counts as declared when `{"outcome": word}` alone passes one of the
/// three schemas; `outcome` is their only required key.
fn declared_by_a_session_schema(word: &str) -> bool {
    let reply = json!({"outcome": word});
    [
        cerebellum::browser_session::BROWSER_LAUNCH,
        cerebellum::browser_session::BROWSER_STATUS,
        cerebellum::browser_session::BROWSER_CLOSE,
    ]
    .iter()
    .any(|capability| cerebellum::browser::validate_browser_result(capability, &reply).is_ok())
}

/// Every `"outcome": "<word>"` literal on one line, spacing tolerated.
fn outcome_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut rest = line;
    while let Some(start) = rest.find("\"outcome\"") {
        rest = &rest[start + "\"outcome\"".len()..];
        let after = rest.trim_start();
        let Some(after) = after.strip_prefix(':') else {
            continue;
        };
        let after = after.trim_start();
        let Some(after) = after.strip_prefix('"') else {
            continue;
        };
        if let Some(end) = after.find('"') {
            words.push(after[..end].to_string());
        }
    }
    words
}

/// A `detail` key whose value is anything but an object literal: a string
/// literal, a `format!`, or a variable holding text.
fn has_string_detail(line: &str) -> bool {
    let mut rest = line;
    while let Some(start) = rest.find("\"detail\"") {
        rest = &rest[start + "\"detail\"".len()..];
        let after = rest.trim_start();
        let value = if let Some(value) = after.strip_prefix(':') {
            value
        } else if let Some(value) = after.strip_prefix(']') {
            // `reply["detail"] = ...`
            match value.trim_start().strip_prefix('=') {
                Some(value) => value,
                None => continue,
            }
        } else {
            continue;
        };
        let value = value.trim_start();
        // A key with its value on the next line is not judged here; every
        // object-valued `detail` in this crate opens its brace on the key line.
        if value.is_empty() {
            continue;
        }
        if !(value.starts_with('{') || value.starts_with("json!({")) {
            return true;
        }
    }
    false
}

/// Lines of one function, found by its signature and ended by brace balance.
fn function_lines(source: &str, signature: &str) -> Vec<(usize, String)> {
    let mut kept = Vec::new();
    let mut depth = 0_i32;
    let mut inside = false;
    let mut opened = false;
    for (index, line) in source.lines().enumerate() {
        if !inside {
            if line.contains(signature) {
                inside = true;
            } else {
                continue;
            }
        }
        kept.push((index + 1, line.to_string()));
        let opens = line.matches('{').count() as i32;
        let closes = line.matches('}').count() as i32;
        if opens > 0 {
            opened = true;
        }
        depth += opens - closes;
        if opened && depth <= 0 {
            break;
        }
    }
    kept
}

#[test]
fn the_scan_reads_outcome_words_and_string_details_the_way_they_are_written() {
    assert_eq!(
        outcome_words(r#"json!({"outcome": "a", "stage": "s"}); json!({"outcome":"b"})"#),
        vec!["a".to_string(), "b".to_string()]
    );
    assert!(outcome_words(r#".get("outcome")"#).is_empty());
    assert!(has_string_detail(r#""detail": format!("{error:?}"),"#));
    assert!(has_string_detail(r#""detail": "JournalTerminalization","#));
    assert!(has_string_detail(
        r#"reply["detail"] = Value::String(text);"#
    ));
    assert!(!has_string_detail(
        r#""detail": {"field": f, "reason_code": r},"#
    ));
    assert!(!has_string_detail(
        r#"assert!(refusal.get("detail").is_none());"#
    ));
}

#[test]
fn the_scan_skips_test_modules_and_keeps_production_lines() {
    let source = "fn a() { json!({\"outcome\": \"kept_a\"}); }\n\
                  #[cfg(test)]\n\
                  mod tests {\n\
                  fn t() { json!({\"outcome\": \"skipped\"}); }\n\
                  }\n\
                  #[cfg(all(test, target_os = \"linux\"))]\n\
                  mod linux_tests {\n\
                  fn t() { json!({\"outcome\": \"skipped_too\"}); }\n\
                  }\n\
                  #[cfg(test)]\n\
                  #[test]\n\
                  fn lone() {\n\
                  json!({\"outcome\": \"skipped_lone\"});\n\
                  }\n\
                  fn b() { json!({\"outcome\": \"kept_b\"}); }\n";
    let words: Vec<String> = source_scan::shipped_lines(source)
        .into_iter()
        .flat_map(|(_, line)| outcome_words(&line))
        .collect();
    assert_eq!(words, vec!["kept_a".to_string(), "kept_b".to_string()]);
}
