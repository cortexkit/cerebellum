//! Rejects test code that spawns a browser outside the reviewed paths. On
//! macOS, unit-test spawns through the test helper are checked for headless
//! mode and recorded.

use super::disclaimed_binary_paths::{tokens, Token, TokenKind};
use super::support::source_scan;
use std::path::{Path, PathBuf};

fn rust_files(directory: &Path, files: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).expect("read browser test sources") {
        let path = entry.expect("source entry").path();
        if path.is_dir() {
            rust_files(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

fn test_module_files(files: &[PathBuf]) -> Vec<PathBuf> {
    let mut selected = source_scan::test_only_module_files(files);
    loop {
        let previous = selected.len();
        for file in files {
            let source = std::fs::read_to_string(file).expect("read test module declarations");
            let tests = if selected.contains(file)
                || file.components().any(|part| part.as_os_str() == "tests")
            {
                source
            } else {
                source_scan::test_source(&source)
            };
            let words = tokens(&tests);
            // Explicit #[path] test modules do not follow Rust's usual file
            // naming rules. Follow their helpers as well as conventional modules.
            for attribute in words.windows(6) {
                if attribute[0].text == "#"
                    && attribute[1].text == "["
                    && attribute[2].text == "path"
                    && attribute[3].text == "="
                    && attribute[4].kind == TokenKind::Literal
                    && attribute[5].text == "]"
                {
                    let module = file
                        .parent()
                        .unwrap()
                        .join(&attribute[4].text)
                        .canonicalize()
                        .expect("explicit test module exists");
                    for candidate in files {
                        // Compare resolved paths: a file reached through a
                        // symlink (macOS /var and /tmp, a target directory on
                        // another volume) must still match its #[path] module.
                        let Ok(resolved) = candidate.canonicalize() else {
                            continue;
                        };
                        if (resolved == module || resolved.starts_with(module.with_extension("")))
                            && !selected.contains(candidate)
                        {
                            selected.push(candidate.clone());
                        }
                    }
                }
            }
        }
        if selected.len() == previous {
            return selected;
        }
    }
}

fn fixture_binding(path: &str, before: &[Token], name: &str) -> bool {
    let Some(binding) = before
        .windows(3)
        .rposition(|words| words[0].text == "let" && words[1].text == name && words[2].text == "=")
    else {
        return false;
    };
    let expression: Vec<&str> = before[binding + 3..]
        .iter()
        .map(|token| token.text.as_str())
        .collect();
    expression.starts_with(&["std", "::", "env", "::", "current_exe", "(", ")"])
        || (path == "cerebellum/tests/conformance.rs"
            && expression.starts_with(&["support", "::", "daemon_binary", "(", "ckdev-cerebellum"]))
        || (path == "cerebellum/src/browser_launch_service.rs"
            && expression.starts_with(&[
                "crate",
                "::",
                "content_named_fixture",
                "::",
                "content_named_fixture",
                "(",
                "chromium-named",
                ",",
                "Chromium",
                ",",
                "&",
                "bytes",
            ]))
        || (path == "cerebellum-macos/src/launch.rs"
            && expression.starts_with(&["relocated_test_executable", "(", ")"]))
        || (path == "cerebellum-macos/tests/preview_hide.rs"
            && name == "child"
            && preview_skip_relocation(before, binding, &expression))
}

// Integration tests cannot call launch.rs's cfg(test) relocation helper.
// preview_hide instead copies its own binary into a private /tmp directory;
// approve that provenance only, never an arbitrary executable named `child`.
fn preview_skip_relocation(before: &[Token], binding: usize, expression: &[&str]) -> bool {
    let child = ["directory", ".", "join", "(", "preview-hide", ")", ";"];
    if !expression.starts_with(&child) {
        return false;
    }
    let words: Vec<&str> = before[..binding]
        .iter()
        .map(|token| token.text.as_str())
        .collect();
    let last_binding = |name| {
        words
            .windows(3)
            .rposition(|w| w == ["let", name, "="])
            .map(|at| &words[at + 3..])
    };
    let own_binary = last_binding("executable").is_some_and(|value| {
        value.starts_with(&["std", "::", "env", "::", "current_exe", "(", ")"])
    });
    let private_directory = last_binding("directory").is_some_and(|value| {
        value.starts_with(&[
            "std",
            "::",
            "path",
            "::",
            "PathBuf",
            "::",
            "from",
            "(",
            "format",
            "!",
            "(",
            "/tmp/cerebellum-preview-skip-{}-{nonce}",
            ",",
            "std",
            "::",
            "process",
            "::",
            "id",
            "(",
            ")",
        ])
    });
    let create = [
        "std",
        "::",
        "fs",
        "::",
        "DirBuilder",
        "::",
        "new",
        "(",
        ")",
        ".",
        "mode",
        "(",
        "0o700",
        ")",
        ".",
        "create",
        "(",
        "&",
        "directory",
        ")",
    ];
    let copy = [
        "std",
        "::",
        "fs",
        "::",
        "copy",
        "(",
        "executable",
        ",",
        "&",
        "child",
        ")",
    ];
    own_binary
        && private_directory
        && words.windows(create.len()).any(|w| w == create)
        && expression[child.len()..]
            .windows(copy.len())
            .any(|w| w == copy)
}

fn violations(path: &str, source: &str) -> Vec<String> {
    let tokens = tokens(source);
    let mut found = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        if token.kind != TokenKind::Identifier {
            continue;
        }
        let at = |offset: usize| tokens.get(index + offset).map(|token| token.text.as_str());
        if token.text == "Command" && at(1) == Some("as") {
            found.push(format!(
                "{}: Command aliases bypass the test launch scan",
                token.line
            ));
        }
        let raw_barrier = matches!(token.text.as_str(), "cerebellum_macos" | "cerebellum_linux")
            && at(1) == Some("::")
            && at(2).is_some_and(|name| name.starts_with("spawn_barred"));
        let bare_barrier = token.text.starts_with("spawn_barred")
            && at(1) == Some("(")
            && !index.checked_sub(1).is_some_and(|previous| {
                matches!(tokens[previous].text.as_str(), "fn" | "." | "::")
            });
        let platform_launcher = matches!(
            token.text.as_str(),
            "MacOsProcessLauncher" | "LinuxProcessLauncher"
        ) && at(1) == Some("::")
            && at(2) == Some("new");
        // On macOS, unit tests reach the platform launcher's cfg(test) spawn
        // helper, which checks for headless mode. Integration tests link the
        // shipped library, where that helper is absent, so they must not
        // construct a platform launcher at all.
        if platform_launcher && !path.starts_with("cerebellum/src/") {
            found.push(format!(
                "{}: platform launcher bypasses the test seam",
                token.line
            ));
        }
        if raw_barrier || bare_barrier {
            let argument = if bare_barrier { 2 } else { 4 };
            let fixed_fixture = at(argument) == Some("Path")
                && at(argument + 1) == Some("::")
                && at(argument + 2) == Some("new")
                && at(argument + 3) == Some("(")
                && matches!(at(argument + 4), Some("/bin/sleep" | "/bin/sh"));
            let name = if at(argument) == Some("&") {
                at(argument + 1)
            } else {
                at(argument)
            };
            let self_fixture = path == "cerebellum-macos/src/launch.rs"
                && name.is_some_and(|name| fixture_binding(path, &tokens[..index], name));
            if !fixed_fixture && !self_fixture {
                found.push(format!(
                    "{}: raw browser barrier bypasses test_browser",
                    token.line
                ));
            }
        }
        if token.text != "Command" || at(1) != Some("::") || at(2) != Some("new") {
            continue;
        }
        let argument = tokens.get(index + 4);
        let fixed_cli = argument.is_some_and(|arg| {
            arg.kind == TokenKind::Literal
                && matches!(
                    arg.text.as_str(),
                    "/bin/sh"
                        | "/bin/sleep"
                        | "/bin/ps"
                        | "/bin/kill"
                        | "kill"
                        | "/usr/bin/sqlite3"
                        | "/usr/sbin/ioreg"
                )
        });
        let self_reexec = at(4) == Some("std")
            && at(5) == Some("::")
            && at(6) == Some("env")
            && at(7) == Some("::")
            && at(8) == Some("current_exe");
        // Permit known self-reexec bindings, not arbitrary variables with the
        // same names. A new dynamic executable needs review of its provenance.
        let name = if at(4) == Some("&") { at(5) } else { at(4) };
        let relocated_fixture =
            name.is_some_and(|name| fixture_binding(path, &tokens[..index], name));
        if !fixed_cli && !self_reexec && !relocated_fixture {
            found.push(format!(
                "{}: Command executable must use a reviewed fixture or test_browser",
                token.line
            ));
        }
    }
    found
}

#[test]
fn test_browser_spawns_cannot_bypass_the_headless_helper() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut files = Vec::new();
    for package in ["cerebellum", "cerebellum-macos"] {
        for directory in ["src", "tests", "examples"] {
            rust_files(&crates.join(package).join(directory), &mut files);
        }
    }
    let test_modules = test_module_files(&files);
    let mut failures = Vec::new();
    let mut scanned = 0;
    for file in files {
        let relative = file.strip_prefix(crates).unwrap().to_str().unwrap();
        if matches!(
            relative,
            "cerebellum/src/test_browser.rs" | "cerebellum/tests/it/tests_never_headed.rs"
        ) {
            continue;
        }
        let source = std::fs::read_to_string(&file).expect("read test source");
        let source = if relative.contains("/tests/") || test_modules.contains(&file) {
            source
        } else {
            // Cargo runs example test functions, not their manually invoked main functions.
            source_scan::test_source(&source)
        };
        scanned += 1;
        failures.extend(
            violations(relative, &source)
                .into_iter()
                .map(|failure| format!("{relative}:{failure}")),
        );
    }
    assert!(scanned > 100, "the scan must visit the real source tree");
    assert!(
        failures.is_empty(),
        "test browser launch bypasses:\n{}",
        failures.join("\n")
    );
}

#[test]
fn detects_literal_dynamic_and_barrier_browser_launches() {
    for source in [
        r#"Command::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome").spawn();"#,
        "std::process::Command :: new (&configured_executable).spawn();",
        "cerebellum_macos::spawn_barred(&chrome, &args, &[], 3, 4);",
        "cerebellum_linux::spawn_barred(&browser, &args);",
        "spawn_barred(&chrome, &args, &[], 3, 4);",
        "MacOsProcessLauncher::new(3, 4);",
        "use std::process::Command as Browser; Browser::new(&chrome).spawn();",
    ] {
        assert!(
            !violations("cerebellum/tests/planted.rs", source).is_empty(),
            "missed {source}"
        );
    }
}

#[test]
fn only_the_reviewed_preview_skip_self_binary_relocation_is_allowed() {
    let path = "cerebellum-macos/tests/preview_hide.rs";
    let source = r#"
        let executable = std::env::current_exe().unwrap();
        let directory = std::path::PathBuf::from(format!(
            "/tmp/cerebellum-preview-skip-{}-{nonce}", std::process::id()
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let child = directory.join("preview-hide");
        std::fs::copy(executable, &child).unwrap();
        Command::new(&child).output();
    "#;
    assert!(violations(path, source).is_empty());
    assert_eq!(
        violations("cerebellum-macos/tests/unreviewed.rs", source).len(),
        1
    );
    for (old, new) in [
        ("std::env::current_exe()", "configured_executable()"),
        ("copy(executable, &child)", "copy(browser, &child)"),
        ("copy(executable, &child)", "metadata(&child)"),
        (
            "directory.join(\"preview-hide\")",
            "directory.join(\"browser\")",
        ),
        (
            "/tmp/cerebellum-preview-skip-{}-{nonce}",
            "/tmp/shared-{}-{nonce}",
        ),
        (".mode(0o700)", ".mode(0o777)"),
        (
            "Command::new",
            "let child = configured_executable(); Command::new",
        ),
    ] {
        let planted = source.replace(old, new);
        assert_ne!(source, planted, "control did not mutate {old}");
        assert_eq!(
            violations(path, &planted).len(),
            1,
            "unreviewed binding escaped: {new}"
        );
    }
}

#[test]
fn test_selection_includes_cfg_test_and_leaves_manual_probes_alone() {
    let source = r#"
        fn main() { Command::new(&chrome).spawn(); }
        #[cfg(all(test, target_os = "macos"))]
        mod tests { fn browser() { Command::new(&chrome).spawn(); } }
    "#;
    let tests = source_scan::test_source(source);
    assert_eq!(violations("cerebellum/examples/probe.rs", &tests).len(), 1);
    assert!(violations(
        "cerebellum/tests/planted.rs",
        "test_browser::spawn_barred(&chrome, &args, &[], 3, 4);"
    )
    .is_empty());
    assert!(violations(
        "cerebellum/tests/planted.rs",
        r#"// Command::new(&chrome)
        const NOTE: &str = "cerebellum_macos::spawn_barred(&chrome)";"#
    )
    .is_empty());
}

#[test]
fn follows_explicitly_named_test_helpers() {
    let tree = source_scan::scratch_directory("headless-source-scan");
    let root = tree.join("lib.rs");
    let helper = tree.join("fixture_shared.rs");
    std::fs::write(
        &root,
        "#[cfg(test)] #[path = \"fixture_shared.rs\"] mod tests;",
    )
    .unwrap();
    std::fs::write(
        &helper,
        "fn launch() { Command::new(&configured).spawn(); }",
    )
    .unwrap();
    let modules = test_module_files(&[root, helper.clone()]);
    assert!(modules.contains(&helper));
    assert_eq!(
        violations(
            "cerebellum/src/fixture_shared.rs",
            &std::fs::read_to_string(helper).unwrap()
        )
        .len(),
        1
    );
    std::fs::remove_dir_all(tree).unwrap();
}
