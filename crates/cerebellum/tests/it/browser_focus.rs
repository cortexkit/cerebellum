//! Background browser actions must not raise Chrome over the person's work.
//! Only the explicit present handoff may front its page.

use std::path::{Path, PathBuf};

use crate::support::source_scan;

fn production_sources(root: &Path) -> Vec<PathBuf> {
    let mut directories = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(directory).expect("read production source directory") {
            let path = entry.expect("read production source entry").path();
            if path.is_dir() {
                directories.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path);
            }
        }
    }
    files
}

fn outside_present(relative: &str, source: &str) -> Vec<usize> {
    // Retain literals for the command scan, but exclude test-only code. The
    // code-only view locates braces without counting JavaScript or comments.
    let mut lines = vec![String::new(); source.lines().count() + 1];
    for (number, line) in source_scan::shipped_lines(source) {
        lines[number - 1] = line;
    }
    let shipped = lines.join("\n");
    let code = source_scan::shipped_code(&shipped);
    let code_chars: Vec<char> = code.chars().collect();
    let allowed = if relative == "browser/navigation/mod.rs" {
        assert_eq!(
            code.matches("pub fn present(").count(),
            1,
            "the scan must locate exactly one production present handoff"
        );
        let byte_start = code.find("pub fn present(").unwrap();
        let start = code[..byte_start].chars().count();
        let body = start
            + code_chars[start..]
                .iter()
                .position(|character| *character == '{')
                .unwrap();
        let mut depth = 0;
        let end = (body..code_chars.len())
            .find(|index| {
                match code_chars[*index] {
                    '{' => depth += 1,
                    '}' => depth -= 1,
                    _ => {}
                }
                depth == 0
            })
            .expect("present body ends");
        let handoff: String = shipped.chars().skip(body).take(end - body + 1).collect();
        assert!(
            handoff.contains("\"Page.bringToFront\""),
            "the allowed handoff must contain the real fronting command"
        );
        Some(start..end + 1)
    } else {
        None
    };
    let characters: Vec<char> = shipped.chars().collect();
    let command: Vec<char> = "Page.bringToFront".chars().collect();
    characters
        .windows(command.len())
        .enumerate()
        .filter(|(index, window)| {
            *window == command.as_slice()
                && !allowed
                    .as_ref()
                    .is_some_and(|allowed| allowed.contains(index))
        })
        .map(|(index, _)| {
            characters[..index]
                .iter()
                .filter(|character| **character == '\n')
                .count()
                + 1
        })
        .collect()
}

#[test]
fn browser_only_present_fronts() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let files = production_sources(&root);
    assert!(
        files.len() > 50,
        "the scan must cover all production sources, including browser code outside its module directory"
    );
    let test_files = source_scan::test_only_module_files(&files);
    let mut violations = Vec::new();
    let mut handoffs = 0;
    let mut scanned = 0;
    for file in files.iter().filter(|file| !test_files.contains(file)) {
        scanned += 1;
        let relative = file
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if relative == "browser/navigation/mod.rs" {
            handoffs += 1;
        }
        let source = std::fs::read_to_string(file).expect("read browser production source");
        violations.extend(
            outside_present(&relative, &source)
                .into_iter()
                .map(|line| format!("{relative}:{line}")),
        );
    }
    println!("scanned {scanned} production source files for unauthorized browser fronting");
    assert_eq!(
        handoffs, 1,
        "the production present implementation was scanned"
    );
    assert!(
        violations.is_empty(),
        "only browser.present may front Chrome; unexpected Page.bringToFront at {violations:?}"
    );
}

#[test]
fn browser_focus_scanner_sees_planted_fronting() {
    let source = "pub fn present() { command(\"Page.bringToFront\"); }\nfn type_field() { command(\"Page.bringToFront\"); }\n#[cfg(test)] mod tests { fn fixture() { command(\"Page.bringToFront\"); } }";
    assert_eq!(
        outside_present("browser/navigation/mod.rs", source),
        vec![2]
    );
    assert_eq!(
        outside_present(
            "browser/navigation/typing.rs",
            "fn type_field() { command(\"Page.bringToFront\"); }"
        ),
        vec![1]
    );
}
