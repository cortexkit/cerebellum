//! The token that lets the real pointer be driven is minted in one place.
//!
//! `OnceDispatchToken` is what the global dispatch path demands before it
//! posts to the one pointer every application shares: it stands for a person
//! having agreed to hand that pointer over. The agreement is the takeover
//! grant, checked in `computer_grants.rs`, and the token must come from that
//! check and nowhere else.
//!
//! The compiler cannot hold that line. The token's type lives in
//! `cerebellum-core`, below both the dispatch crate that demands it and this
//! crate that checks the grant, so its constructor has to be public, and a
//! public constructor can be called from anywhere in the process. A second
//! call site would compile, pass every behavioural test, and post to the
//! pointer with no one having been asked. So the fence is structural: every
//! production source of the workspace is scanned, and exactly one
//! construction site is allowed, inside the takeover grant check.

use std::path::{Path, PathBuf};

use crate::support::source_scan;

/// Construction sites allowed outside test code, with the reason each exists,
/// as paths under the workspace's `crates` directory.
const ALLOWED_CALLS: &[(&str, &str)] = &[(
    "cerebellum/src/computer_grants.rs",
    "ComputerGrants::require_takeover_dispatch, after the takeover grant is held",
)];

/// The one place the token's fields are filled in: the constructor itself.
const ALLOWED_LITERALS: &[(&str, &str)] = &[(
    "cerebellum-core/src/consent.rs",
    "the body of OnceDispatchToken::admitted_by_takeover_grant",
)];

#[test]
fn the_pointer_dispatch_token_is_minted_only_by_the_takeover_grant_check() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("this crate lives under the workspace's crates directory")
        .to_path_buf();
    let mut calls = Vec::new();
    let mut literals = Vec::new();
    let mut files_scanned = 0;
    // Files an out-of-line test module loads are test code throughout.
    let files = workspace_sources(&crates);
    let test_files = source_scan::test_only_module_files(&files);
    for file in files.iter().filter(|file| !test_files.contains(file)) {
        files_scanned += 1;
        let relative = file
            .strip_prefix(&crates)
            .expect("sources live under the crates directory")
            .to_string_lossy()
            .replace('\\', "/");
        let source = std::fs::read_to_string(file).expect("read a workspace source file");
        for (line_number, line) in source_scan::shipped_lines(&source) {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            if code.contains("admitted_by_takeover_grant(")
                && !code.contains("fn admitted_by_takeover_grant(")
            {
                calls.push((relative.clone(), line_number, code.to_string()));
            }
            // The field is private, so only the defining file can fill it in;
            // a second constructor there would bypass the call-site check.
            if relative == ALLOWED_LITERALS[0].0
                && (code.contains("Self { action") || code.contains("OnceDispatchToken { action"))
            {
                literals.push((relative.clone(), line_number, code.to_string()));
            }
        }
    }

    assert!(
        files_scanned > 50,
        "the scan found only {files_scanned} sources under {}, so it proved nothing",
        crates.display()
    );
    assert_sites(
        "OnceDispatchToken::admitted_by_takeover_grant is called",
        ALLOWED_CALLS,
        &calls,
    );
    assert_sites(
        "an OnceDispatchToken is built field by field",
        ALLOWED_LITERALS,
        &literals,
    );
}

fn assert_sites(what: &str, allowed: &[(&str, &str)], found: &[(String, usize, String)]) {
    let stray = found
        .iter()
        .any(|(path, _, _)| !allowed.iter().any(|(allowed, _)| allowed == path));
    assert!(
        !stray && found.len() == allowed.len(),
        "{what} outside the takeover grant check. The token is the proof that a person \
         agreed to hand over the pointer; take it from \
         ComputerGrants::require_takeover_dispatch instead of minting one.\nallowed:\n{}\nfound:\n{}",
        allowed
            .iter()
            .map(|(path, reason)| format!("  {path}: {reason}"))
            .collect::<Vec<_>>()
            .join("\n"),
        found
            .iter()
            .map(|(path, line, text)| format!("  {path}:{line}: {text}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Every `.rs` file under each workspace crate's `src` directory. Tests,
/// examples and benches are separate targets outside `src` and are not
/// production paths.
fn workspace_sources(crates: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let Ok(members) = std::fs::read_dir(crates) else {
        return files;
    };
    let mut stack: Vec<PathBuf> = members
        .flatten()
        .map(|member| member.path().join("src"))
        .filter(|src| src.is_dir())
        .collect();
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

/// Unit tests build tokens of their own to drive the dispatch path, and that
/// is fine: they are not part of a running module. This checks the scan sees
/// that the shared skipper sets test code aside, and keeps the production
/// lines around it.
#[test]
fn the_scan_skips_test_modules_and_keeps_production_lines() {
    let source = "fn a() { let _ = OnceDispatchToken::admitted_by_takeover_grant(); }\n\
                  #[cfg(test)]\n\
                  mod tests {\n\
                  let _ = OnceDispatchToken::admitted_by_takeover_grant();\n\
                  }\n\
                  #[cfg(all(test, target_os = \"macos\"))]\n\
                  fn helper(\n\
                  ) -> Token {\n\
                  OnceDispatchToken::admitted_by_takeover_grant()\n\
                  }\n\
                  #[cfg(test)]\n\
                  use something;\n\
                  fn b() { let _ = OnceDispatchToken::admitted_by_takeover_grant(); }\n";
    let kept: Vec<_> = source_scan::shipped_lines(source)
        .into_iter()
        .filter(|(_, line)| line.contains("admitted_by_takeover_grant("))
        .collect();

    assert_eq!(
        kept.len(),
        2,
        "the scan must keep both production lines and drop the one inside the test module: {kept:?}"
    );
    assert!(kept.iter().any(|(_, line)| line.contains("fn a()")));
    assert!(kept.iter().any(|(_, line)| line.contains("fn b()")));
}
