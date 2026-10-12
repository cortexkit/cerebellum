//! Test executables handed to the daemon must live on the internal disk.
#[allow(dead_code)]
#[path = "../support/mod.rs"]
mod support;

use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq)]
enum TokenKind {
    Identifier,
    Literal,
    Punctuation,
}

#[derive(Debug)]
struct Token {
    text: String,
    kind: TokenKind,
    line: usize,
}

fn tokens(source: &str) -> Vec<Token> {
    let chars: Vec<char> = source.chars().collect();
    let mut found = Vec::new();
    let mut index = 0;
    let mut line = 1;
    while index < chars.len() {
        let start = index;
        let token_line = line;
        let character = chars[index];
        if character.is_whitespace() {
            if character == '\n' {
                line += 1;
            }
            index += 1;
            continue;
        }
        if character == '/' && chars.get(index + 1) == Some(&'/') {
            index += 2;
            while index < chars.len() && chars[index] != '\n' {
                index += 1;
            }
            continue;
        }
        if character == '/' && chars.get(index + 1) == Some(&'*') {
            index += 2;
            let mut depth = 1;
            while index < chars.len() && depth > 0 {
                if chars[index] == '/' && chars.get(index + 1) == Some(&'*') {
                    depth += 1;
                    index += 2;
                } else if chars[index] == '*' && chars.get(index + 1) == Some(&'/') {
                    depth -= 1;
                    index += 2;
                } else {
                    index += 1;
                }
            }
            line += chars[start..index].iter().filter(|&&c| c == '\n').count();
            continue;
        }

        if let Some((quote, hashes)) = raw_string_start(&chars, index) {
            let content_start = quote + 1;
            index = content_start;
            while index < chars.len()
                && !(chars[index] == '"'
                    && (0..hashes).all(|offset| chars.get(index + 1 + offset) == Some(&'#')))
            {
                index += 1;
            }
            let content_end = index;
            index = (index + 1 + hashes).min(chars.len());
            let text = chars[content_start..content_end].iter().collect();
            line += chars[start..index].iter().filter(|&&c| c == '\n').count();
            found.push(Token {
                text,
                kind: TokenKind::Literal,
                line: token_line,
            });
            continue;
        }

        let quote = if character == '"' {
            Some(index)
        } else if character == 'b' && chars.get(index + 1) == Some(&'"') {
            Some(index + 1)
        } else {
            None
        };
        if let Some(quote) = quote {
            index = quote + 1;
            let content_start = index;
            while index < chars.len() && chars[index] != '"' {
                if chars[index] == '\\' {
                    index += 1;
                }
                index += 1;
            }
            let content_end = index;
            index = (index + 1).min(chars.len());
            let text = chars[content_start..content_end].iter().collect();
            line += chars[start..index].iter().filter(|&&c| c == '\n').count();
            found.push(Token {
                text,
                kind: TokenKind::Literal,
                line: token_line,
            });
            continue;
        }

        if character == '\'' {
            let mut end = index + 1;
            if chars.get(end) == Some(&'\\') {
                end += 2;
            } else {
                end += 1;
            }
            if chars.get(end) == Some(&'\'') {
                index = end + 1;
                continue;
            }
        }

        if character.is_ascii_alphanumeric() || character == '_' {
            index += 1;
            while index < chars.len()
                && (chars[index].is_ascii_alphanumeric() || chars[index] == '_')
            {
                index += 1;
            }
            found.push(Token {
                text: chars[start..index].iter().collect(),
                kind: TokenKind::Identifier,
                line: token_line,
            });
            continue;
        }

        if character == ':' && chars.get(index + 1) == Some(&':') {
            index += 2;
            found.push(Token {
                text: "::".into(),
                kind: TokenKind::Punctuation,
                line: token_line,
            });
        } else {
            index += 1;
            found.push(Token {
                text: character.to_string(),
                kind: TokenKind::Punctuation,
                line: token_line,
            });
        }
    }
    found
}

fn raw_string_start(chars: &[char], start: usize) -> Option<(usize, usize)> {
    let mut index = if chars.get(start) == Some(&'b') && chars.get(start + 1) == Some(&'r') {
        start + 2
    } else if chars.get(start) == Some(&'r') {
        start + 1
    } else {
        return None;
    };
    let mut hashes = 0;
    while chars.get(index) == Some(&'#') {
        hashes += 1;
        index += 1;
    }
    (chars.get(index) == Some(&'"')).then_some((index, hashes))
}

fn argument_end(tokens: &[Token], start: usize, outer_close: &str) -> usize {
    let mut nested = Vec::new();
    for (index, token) in tokens.iter().enumerate().skip(start) {
        if nested.is_empty() && (token.text == "," || token.text == outer_close) {
            return index;
        }
        match token.text.as_str() {
            "(" => nested.push(")"),
            "[" => nested.push("]"),
            "{" => nested.push("}"),
            ")" | "]" | "}" if nested.last() == Some(&token.text.as_str()) => {
                nested.pop();
            }
            ")" | "]" | "}" if nested.is_empty() => return index,
            _ => {}
        }
    }
    tokens.len()
}

fn contains_raw_binary_source(tokens: &[Token], start: usize, end: usize) -> bool {
    (start..end).any(|index| {
        let token = &tokens[index];
        let cargo_binary = token.text == "env"
            && tokens.get(index + 1).is_some_and(|token| token.text == "!")
            && tokens.get(index + 2).is_some_and(|token| token.text == "(")
            && tokens.get(index + 3).is_some_and(|token| {
                token.kind == TokenKind::Literal && token.text.starts_with("CARGO_BIN_EXE_")
            });
        cargo_binary
            || (token.text == "current_exe"
                && tokens.get(index + 1).is_some_and(|token| token.text == "("))
    })
}

fn relocated_binary_argument(tokens: &[Token], start: usize, end: usize) -> bool {
    for (index, token) in tokens.iter().enumerate().take(end).skip(start) {
        if token.text != "daemon_binary"
            || !tokens.get(index + 1).is_some_and(|token| token.text == "(")
        {
            continue;
        }
        let mut depth = 0;
        for close in index + 1..end {
            match tokens[close].text.as_str() {
                "(" => depth += 1,
                ")" => {
                    depth -= 1;
                    if depth == 0 {
                        if contains_raw_binary_source(tokens, index + 2, close) {
                            return true;
                        }
                        break;
                    }
                }
                _ => {}
            }
        }
    }
    false
}

fn unrelocated_binary_argument(tokens: &[Token], start: usize, outer_close: &str) -> bool {
    let end = argument_end(tokens, start, outer_close);
    contains_raw_binary_source(tokens, start, end) && !relocated_binary_argument(tokens, start, end)
}

fn violations(source: &str) -> Vec<String> {
    let tokens = tokens(source);
    let mut found = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        let is_program_key = token.text == "program"
            && (token.kind == TokenKind::Literal || token.kind == TokenKind::Identifier)
            && tokens.get(index + 1).is_some_and(|next| next.text == ":");
        if is_program_key && unrelocated_binary_argument(&tokens, index + 2, "}") {
            found.push(format!(
                "line {}: raw binary assigned to module program",
                token.line
            ));
        }

        let target_method =
            token.text == "with_privacy_trampoline" || token.text.starts_with("spawn_barred");
        if target_method
            && tokens.get(index + 1).is_some_and(|next| next.text == "(")
            && unrelocated_binary_argument(&tokens, index + 2, ")")
        {
            found.push(format!(
                "line {}: raw binary passed to {}",
                token.line, token.text
            ));
        }
    }
    found
}

fn rust_files(directory: &Path, files: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).expect("read test source directory") {
        let path = entry.expect("read test source entry").path();
        if path.is_dir() {
            rust_files(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

#[test]
fn daemon_and_disclaimed_test_launches_use_internal_disk_copies() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let tests = root.join("tests");
    let mut files = Vec::new();
    rust_files(&tests, &mut files);
    files.sort();

    let mut violations_found = Vec::new();
    for file in &files {
        let source = std::fs::read_to_string(file).expect("read Rust test source");
        for violation in violations(&source) {
            let relative = file.strip_prefix(root).expect("test source is in crate");
            violations_found.push(format!("{}: {violation}", relative.display()));
        }
    }
    assert!(
        !files.is_empty(),
        "the source scan must inspect Rust test files"
    );
    assert!(
        violations_found.is_empty(),
        "daemon and disclaimed launches must use daemon_binary copies:\n{}",
        violations_found.join("\n")
    );
}

#[test]
fn source_scan_detects_raw_binary_paths_at_daemon_launch_sites() {
    let source = r#"
        fn bad_launches() {
            let config = json!({ "program": env!("CARGO_BIN_EXE_bad-module") });
            let config = json!({ "program": PathBuf::from(env!("CARGO_BIN_EXE_unrelocated-module")) });
            let config = json!({ program: std::env::current_exe().unwrap() });
            bootstrap.with_privacy_trampoline(env!("CARGO_BIN_EXE_bad-trampoline"));
            spawn_barred(std::env::current_exe().unwrap());
        }
    "#;
    let found = violations(source);
    assert_eq!(found.len(), 5, "scanner missed a planted launch: {found:?}");
}

#[test]
fn source_scan_ignores_comments_and_string_literal_controls() {
    let source = r###"
        // { "program": env!("CARGO_BIN_EXE_in_comment") }
        /* with_privacy_trampoline(std::env::current_exe()) */
        const NOTE: &str = "spawn_barred(env!(\\\"CARGO_BIN_EXE_in_string\\\"))";
        const RAW: &str = r#"{ \"program\": std::env::current_exe() }"#;
    "###;
    assert!(violations(source).is_empty());
}

#[test]
fn source_scan_accepts_helper_wrapped_binary_paths() {
    let source = r#"
        fn safe_launches() {
            let config = json!({ "program": support::daemon_binary(
                "ck-cerebellum", env!("CARGO_BIN_EXE_ck-cerebellum")
            ) });
            bootstrap.with_privacy_trampoline(support::daemon_binary(
                "test-privacy-trampoline", env!("CARGO_BIN_EXE_trampoline")
            ));
            spawn_barred(support::daemon_binary(
                "test-launcher", std::env::current_exe().unwrap()
            ));
        }
    "#;
    assert!(violations(source).is_empty());
}

#[cfg(unix)]
#[test]
fn daemon_binary_is_a_real_executable_copy_under_tmp() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let source = PathBuf::from(env!("CARGO_BIN_EXE_cerebellum-test-nonce-holder"));
    let copied = support::daemon_binary("daemon-copy-control", &source);
    let source_metadata = std::fs::metadata(&source).expect("stat nonce-holder binary");
    let copied_metadata = std::fs::metadata(&copied).expect("stat relocated nonce-holder");
    assert!(
        copied.starts_with("/tmp"),
        "copy is not under /tmp: {}",
        copied.display()
    );
    assert_eq!(
        std::fs::read(&copied).expect("read relocated binary"),
        std::fs::read(&source).expect("read source binary")
    );
    assert_eq!(
        copied_metadata.permissions().mode() & 0o777,
        source_metadata.permissions().mode() & 0o777,
        "relocation preserves executable permissions"
    );
    assert_ne!(
        (copied_metadata.dev(), copied_metadata.ino()),
        (source_metadata.dev(), source_metadata.ino()),
        "the relocated executable must be a copy, not a hard link"
    );
}
