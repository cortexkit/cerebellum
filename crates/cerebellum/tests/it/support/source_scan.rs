//! Shared pieces of the structural source scans: the one place that decides
//! which code is compiled only for tests, a tokenizer that makes matching
//! blind to layout, and the scratch-tree helpers the walk controls use.
//!
//! Every scan that fences shipped code has to set test code aside first, and
//! each used to do it its own way, line by line: one cut from a marker to the
//! next `mod .. {` line, another skipped only modules, and none could tell a
//! `#[cfg(test)]` in a comment or a string from a real one, or a brace in a
//! string from a real one. A scan that drops shipped code reads as clean while
//! looking at less than it guards, so the decision lives here, once, with
//! controls of its own.

use std::path::{Path, PathBuf};

/// The lines of a Rust source file that ship, with their 1-based numbers.
///
/// Every item an attribute marks test-only is removed over its own extent,
/// whatever kind of item it is: a module, `fn`, `impl`, `use`, `const`, a
/// struct field, a statement. Text that belongs to such an item is blanked, so
/// a line shared with shipped code keeps only the shipped part, and a line
/// left empty is dropped. Comments and string literals in shipped code are
/// kept as written; scans decide for themselves whether a mention there
/// counts.
///
/// Markers are found in code only: a `#[cfg(test)]` inside a comment or a
/// string literal marks nothing, and brackets inside either do not count
/// towards an item's extent. `cfg(test)` and `cfg(all(test, ..))` mark an item
/// test-only; `cfg(any(test, ..))` and `cfg(not(test))` code ships and is kept.
///
/// An out-of-line test module (`#[cfg(test)] mod tests;`) loads a whole file;
/// [`test_only_module_files`] finds those files so a walk can leave them out.
pub fn shipped_lines(source: &str) -> Vec<(usize, String)> {
    let original: Vec<char> = source.chars().collect();
    let code = code_only(&original);
    let mut test_only = vec![false; code.len()];
    for (start, end) in test_items(&code) {
        test_only[start..end].fill(true);
    }

    let mut kept = Vec::new();
    let mut line = String::new();
    let mut line_number = 1;
    for (position, &c) in original.iter().enumerate() {
        if c == '\n' {
            if !line.trim().is_empty() {
                kept.push((line_number, std::mem::take(&mut line)));
            }
            line.clear();
            line_number += 1;
        } else {
            line.push(if test_only[position] { ' ' } else { c });
        }
    }
    if !line.trim().is_empty() {
        kept.push((line_number, line));
    }
    kept
}

/// Test-only items, with shipped text blanked and line numbers preserved.
/// Browser launch scans must inspect these items rather than discard them.
pub fn test_source(source: &str) -> String {
    let original: Vec<char> = source.chars().collect();
    let code = code_only(&original);
    let mut selected = vec![false; code.len()];
    for (start, end) in test_items(&code) {
        selected[start..end].fill(true);
    }
    original
        .iter()
        .enumerate()
        .map(|(index, &c)| if selected[index] || c == '\n' { c } else { ' ' })
        .collect()
}

/// The source files among `files` that are out-of-line test modules: each file
/// a `#[cfg(test)] mod name;` declaration loads (`name.rs` or `name/mod.rs`
/// beside the declaring module), and every file beneath that module's
/// directory. None of them ships, but nothing inside them says so.
pub fn test_only_module_files(files: &[PathBuf]) -> Vec<PathBuf> {
    let mut modules = Vec::new();
    for file in files {
        let Ok(source) = std::fs::read_to_string(file) else {
            continue;
        };
        let directory = module_directory(file);
        for name in test_only_module_names(&source) {
            modules.push((directory.join(format!("{name}.rs")), directory.join(&name)));
        }
    }
    files
        .iter()
        .filter(|file| {
            modules.iter().any(|(module_file, module_directory)| {
                *file == module_file || file.starts_with(module_directory)
            })
        })
        .cloned()
        .collect()
}

/// The directory a file's own submodules live in: beside `lib.rs`, `main.rs`
/// and `mod.rs`, and in a directory named for the file otherwise.
fn module_directory(file: &Path) -> PathBuf {
    let parent = file.parent().unwrap_or(Path::new(""));
    match file.file_stem().and_then(|stem| stem.to_str()) {
        Some("lib" | "main" | "mod") | None => parent.to_path_buf(),
        Some(stem) => parent.join(stem),
    }
}

/// The names of modules a source file declares out of line and test-only.
fn test_only_module_names(source: &str) -> Vec<String> {
    let original: Vec<char> = source.chars().collect();
    let code = code_only(&original);
    let mut names = Vec::new();
    for (start, end) in test_items(&code) {
        let text: String = code[start..end].iter().collect();
        let item_tokens = tokens(&[(1, text.as_str())]);
        let words: Vec<&str> = item_tokens.iter().map(|(_, token)| *token).collect();
        // Past the attributes and any visibility, the item must read
        // `mod name ;` exactly.
        let mut index = 0;
        while index < words.len() && words[index] != "mod" {
            index += 1;
        }
        if let [_, name, ";"] = words.get(index..).unwrap_or(&[]) {
            names.push((*name).to_string());
        }
    }
    names
}

/// The `[start, end)` character ranges of every item a test-only attribute
/// marks, attribute included, read from the code-only view.
fn test_items(code: &[char]) -> Vec<(usize, usize)> {
    let mut items = Vec::new();
    let mut index = 0;
    while index < code.len() {
        if let Some(after_attribute) = test_attribute_end(code, index) {
            let end = item_end(code, after_attribute);
            items.push((index, end));
            index = end;
        } else {
            index += 1;
        }
    }
    items
}

/// Shipped Rust code with comments, literals and test-only items blanked.
/// Line breaks and character positions are preserved for structural scans.
pub fn shipped_code(source: &str) -> String {
    let original: Vec<char> = source.chars().collect();
    let mut code = code_only(&original);
    for (start, end) in test_items(&code) {
        for character in &mut code[start..end] {
            if *character != '\n' {
                *character = ' ';
            }
        }
    }
    code.into_iter().collect()
}

/// The source with every comment and the contents of every string and char
/// literal replaced by spaces, line breaks kept, so positions line up with
/// the original. Structure (attributes, brackets) is read from this view only.
fn code_only(source: &[char]) -> Vec<char> {
    let is_identifier = |c: char| c.is_alphanumeric() || c == '_';
    let at = |index: usize| source.get(index).copied();
    let mut code = source.to_vec();
    let mut blank = |from: usize, to: usize| {
        for c in &mut code[from..to.min(source.len())] {
            if *c != '\n' {
                *c = ' ';
            }
        }
    };
    let mut index = 0;
    while index < source.len() {
        let c = source[index];
        if c == '/' && at(index + 1) == Some('/') {
            let end = (index..source.len())
                .find(|&position| source[position] == '\n')
                .unwrap_or(source.len());
            blank(index, end);
            index = end;
        } else if c == '/' && at(index + 1) == Some('*') {
            // Block comments nest in Rust.
            let mut depth = 0;
            let mut position = index;
            while position < source.len() {
                if source[position] == '/' && at(position + 1) == Some('*') {
                    depth += 1;
                    position += 2;
                } else if source[position] == '*' && at(position + 1) == Some('/') {
                    depth -= 1;
                    position += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    position += 1;
                }
            }
            blank(index, position);
            index = position;
        } else if c == '"' {
            let mut position = index + 1;
            while position < source.len() && source[position] != '"' {
                if source[position] == '\\' {
                    position += 1;
                }
                position += 1;
            }
            blank(index, position + 1);
            index = position + 1;
        } else if c == '\'' {
            // A char literal, or else a lifetime, which is left alone.
            if at(index + 1) == Some('\\') {
                let end = (index + 3..source.len())
                    .find(|&position| source[position] == '\'')
                    .unwrap_or(source.len());
                blank(index, end + 1);
                index = end + 1;
            } else if at(index + 2) == Some('\'') {
                blank(index, index + 3);
                index += 3;
            } else {
                index += 1;
            }
        } else if is_identifier(c) {
            // Whole identifiers at a time, so that only a standalone `r` or
            // `br` can open a raw string.
            let start = index;
            while index < source.len() && is_identifier(source[index]) {
                index += 1;
            }
            let word: String = source[start..index].iter().collect();
            if word == "r" || word == "br" {
                let hashes = (index..source.len())
                    .take_while(|&position| source[position] == '#')
                    .count();
                if at(index + hashes) == Some('"') {
                    let mut position = index + hashes + 1;
                    while position < source.len()
                        && !(source[position] == '"'
                            && (1..=hashes).all(|offset| at(position + offset) == Some('#')))
                    {
                        position += 1;
                    }
                    let end = position + 1 + hashes;
                    blank(start, end);
                    index = end;
                }
            }
        } else {
            index += 1;
        }
    }
    code
}

/// If an outer `#[cfg(..)]` attribute whose predicate holds only under test
/// starts at `index`, the position just after its closing `]`.
fn test_attribute_end(code: &[char], index: usize) -> Option<usize> {
    if code[index] != '#' {
        return None;
    }
    let open = (index + 1..code.len()).find(|&position| !code[position].is_whitespace())?;
    if code[open] != '[' {
        return None;
    }
    let mut depth = 0;
    let mut content = String::new();
    for (position, &c) in code.iter().enumerate().skip(open) {
        match c {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    let predicate = content
                        .strip_prefix("[cfg(")
                        .and_then(|rest| rest.strip_suffix(')'))?;
                    return is_test_only(predicate).then_some(position + 1);
                }
            }
            _ => {}
        }
        if !c.is_whitespace() {
            content.push(c);
        }
    }
    None
}

/// Whether a `cfg` predicate, whitespace removed, can hold only in a test
/// build: `test` itself, or an `all(..)` with such a predicate among its
/// arguments. `any(test, ..)` holds in a feature build too, and `not(test)` in
/// every shipped one, so neither qualifies.
fn is_test_only(predicate: &str) -> bool {
    if predicate == "test" {
        return true;
    }
    let Some(arguments) = predicate
        .strip_prefix("all(")
        .and_then(|rest| rest.strip_suffix(')'))
    else {
        return false;
    };
    let mut depth = 0;
    let mut start = 0;
    let mut parts = Vec::new();
    for (position, c) in arguments.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(&arguments[start..position]);
                start = position + 1;
            }
            _ => {}
        }
    }
    parts.push(&arguments[start..]);
    parts.into_iter().any(is_test_only)
}

/// Where the item an attribute applies to ends, scanning from just after the
/// attribute: after its body's closing brace (and a `;` that directly follows,
/// as in `use a::{b};`), after a `;` or a `,` at its own level (a statement,
/// a bodiless item, a field), or just before the bracket that closes the
/// enclosing scope.
///
/// A comma ends only an item that has no item keyword of its own (a field, a
/// struct-literal field, an enum variant, a match arm, a parameter), so the
/// commas in a `where` clause or a generic list do not end the function or
/// `impl` they belong to. Angle brackets are tracked at the item's own level
/// as well, for a field typed `HashMap<K, V>`. Every misjudgement here ends an
/// item early rather than late, which reads test code as shipped code and so
/// errs towards a false alarm, never towards a missed violation.
fn item_end(code: &[char], start: usize) -> usize {
    const ITEM_KEYWORDS: &[&str] = &[
        "fn",
        "impl",
        "struct",
        "enum",
        "union",
        "trait",
        "mod",
        "use",
        "const",
        "static",
        "type",
        "extern",
        "macro_rules",
        "let",
    ];
    let mut depth = 0_i32;
    let mut angle = 0_i32;
    let mut previous = ' ';
    let mut is_item = false;
    let mut word = String::new();
    for (position, &c) in code.iter().enumerate().skip(start) {
        if c.is_alphanumeric() || c == '_' {
            word.push(c);
        } else if !word.is_empty() {
            if depth == 0 && ITEM_KEYWORDS.contains(&word.as_str()) {
                is_item = true;
            }
            word.clear();
        }
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' if depth == 0 => return position,
            ')' | ']' | '}' => {
                depth -= 1;
                if c == '}' && depth == 0 {
                    let after =
                        (position + 1..code.len()).find(|&next| !code[next].is_whitespace());
                    return match after {
                        Some(next) if code[next] == ';' => next + 1,
                        _ => position + 1,
                    };
                }
            }
            ';' if depth == 0 => return position + 1,
            ',' if depth == 0 && angle == 0 && !is_item => return position + 1,
            '<' if depth == 0 => angle += 1,
            '>' if depth == 0 && previous != '-' && previous != '=' => {
                angle = (angle - 1).max(0);
            }
            _ => {}
        }
        if !c.is_whitespace() {
            previous = c;
        }
    }
    code.len()
}

/// Splits numbered lines into tokens, each with the 1-based number of the line
/// it starts on: identifiers (letters, digits and `_`), the path separator
/// `::`, and every other non-space character on its own.
///
/// Whitespace and line breaks only separate tokens, so `SystemClock::new ()`,
/// a call split over several lines and the tidy one-line form all produce the
/// same sequence. Comments and string literals are not recognised: the words
/// inside them come out as ordinary tokens, which keeps the scans flagging a
/// mention there as they always have.
pub fn tokens<'a>(lines: &[(usize, &'a str)]) -> Vec<(usize, &'a str)> {
    let is_identifier = |c: char| c.is_alphanumeric() || c == '_';
    let mut found = Vec::new();
    for &(line_number, line) in lines {
        let mut rest = line;
        while let Some(first) = rest.chars().next() {
            let length = if first.is_whitespace() {
                rest = &rest[first.len_utf8()..];
                continue;
            } else if is_identifier(first) {
                rest.find(|c: char| !is_identifier(c)).unwrap_or(rest.len())
            } else if rest.starts_with("::") {
                2
            } else {
                first.len_utf8()
            };
            found.push((line_number, &rest[..length]));
            rest = &rest[length..];
        }
    }
    found
}

/// A fresh directory under the system temp directory. The walk controls only
/// ever put copied source text in it, never anything executed.
pub fn scratch_directory(label: &str) -> PathBuf {
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
pub fn copy_tree(from: &Path, to: &Path) {
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

/// Planted sources for the skipper's controls: a name, the source's lines, the
/// 1-based lines that must be read as shipped, and those that must not.
type SkipperCase = (
    &'static str,
    &'static [&'static str],
    &'static [usize],
    &'static [usize],
);

const SKIPPER_CASES: &[SkipperCase] = &[
    (
        "a marked module, then shipped code",
        &[
            "#[cfg(test)]",
            "mod tests {",
            "    fn t() {}",
            "}",
            "fn shipped() {}",
        ],
        &[5],
        &[1, 2, 3, 4],
    ),
    (
        "two marked modules with shipped code between and after",
        &[
            "#[cfg(test)]",
            "mod a {",
            "}",
            "fn shipped() {}",
            "#[cfg(test)]",
            "mod b {",
            "}",
            "fn also_shipped() {}",
        ],
        &[4, 8],
        &[1, 2, 3, 5, 6, 7],
    ),
    (
        "a marked fn with generics and a where clause",
        &[
            "#[cfg(test)]",
            "fn helper<R, W>(r: R) -> Result<(), E>",
            "where",
            "    R: Read,",
            "    W: Write,",
            "{",
            "    body();",
            "}",
            "fn shipped() {}",
        ],
        &[9],
        &[1, 2, 3, 4, 5, 6, 7, 8],
    ),
    (
        "a marked const",
        &[
            "#[cfg(test)]",
            "const LIMIT: [u8; 2] = [1, 2];",
            "fn shipped() {}",
        ],
        &[3],
        &[1, 2],
    ),
    (
        "a marked use group",
        &["#[cfg(test)]", "use a::{b, c};", "fn shipped() {}"],
        &[3],
        &[1, 2],
    ),
    (
        "a marked impl",
        &[
            "#[cfg(test)]",
            "impl Probe {",
            "    fn t() {}",
            "}",
            "impl Probe {",
            "    fn shipped() {}",
            "}",
        ],
        &[5, 6, 7],
        &[1, 2, 3, 4],
    ),
    (
        "a marked struct field",
        &[
            "pub struct Planes {",
            "    #[cfg(test)]",
            "    handler: Option<HashMap<K, V>>,",
            "    pub health: Health,",
            "}",
            "fn shipped() {}",
        ],
        &[1, 4, 5, 6],
        &[2, 3],
    ),
    (
        "a marked field in a struct literal",
        &[
            "Planes {",
            "    #[cfg(test)]",
            "    handler: None,",
            "    health: make(),",
            "}",
        ],
        &[1, 4, 5],
        &[2, 3],
    ),
    (
        "a marked type alias over several lines",
        &[
            "#[cfg(test)]",
            "type Handler =",
            "    Arc<dyn Fn() -> Box<dyn Future<Output = ()>>>;",
            "fn shipped() {}",
        ],
        &[4],
        &[1, 2, 3],
    ),
    (
        "a marked statement",
        &[
            "fn run() {",
            "    #[cfg(test)]",
            "    if let Some(hook) = &hook {",
            "        hook();",
            "    }",
            "    shipped();",
            "}",
        ],
        &[1, 6, 7],
        &[2, 3, 4, 5],
    ),
    (
        "stacked attributes and a doc comment",
        &[
            "#[cfg(test)]",
            "#[derive(Debug)]",
            "/// A fixture.",
            "struct Fixture {",
            "    a: u8,",
            "}",
            "fn shipped() {}",
        ],
        &[7],
        &[1, 2, 3, 4, 5, 6],
    ),
    (
        "an out-of-line marked module",
        &["#[cfg(test)]", "mod tests;", "fn shipped() {}"],
        &[3],
        &[1, 2],
    ),
    (
        "a cfg(all(test, ..)) module",
        &[
            "#[cfg(all(test, unix))]",
            "mod unix_tests {",
            "    fn t() {}",
            "}",
            "fn shipped() {}",
        ],
        &[5],
        &[1, 2, 3, 4],
    ),
    (
        "test nested inside all(..)",
        &[
            "#[cfg(all(unix, all(test, feature = \"live\")))]",
            "fn t() {}",
            "fn shipped() {}",
        ],
        &[3],
        &[1, 2],
    ),
    (
        "a brace and a quote in literals inside a marked module",
        &[
            "#[cfg(test)]",
            "mod tests {",
            "    const OPEN: &str = \"{\\\"\";",
            "    const BRACE: char = '{';",
            "    const RAW: &str = r#\"}\"#;",
            "}",
            "fn shipped() {}",
        ],
        &[7],
        &[1, 2, 3, 4, 5, 6],
    ),
    // Not markers: each of these is shipped code from top to bottom.
    (
        "a marker in a line comment",
        &["// #[cfg(test)]", "mod shipped {", "    fn f() {}", "}"],
        &[1, 2, 3, 4],
        &[],
    ),
    (
        "a marker in a block comment",
        &["/* #[cfg(test)] */", "fn shipped() {}"],
        &[1, 2],
        &[],
    ),
    (
        "a marker in a string literal",
        &[
            "const NOTE: &str = \"",
            "#[cfg(test)]",
            "mod tests {\";",
            "fn shipped() {}",
        ],
        &[1, 2, 3, 4],
        &[],
    ),
    (
        "a marker in a raw string literal",
        &[
            "const NOTE: &str = r#\"",
            "#[cfg(test)]",
            "\"#;",
            "fn shipped() {}",
        ],
        &[1, 2, 3, 4],
        &[],
    ),
    (
        "a cfg(any(test, ..)) module, which ships with the feature",
        &[
            "#[cfg(any(test, feature = \"fixtures\"))]",
            "mod fixtures {",
            "    fn f() {}",
            "}",
        ],
        &[1, 2, 3, 4],
        &[],
    ),
    (
        "a cfg(not(test)) module",
        &["#[cfg(not(test))]", "mod shipped {", "    fn f() {}", "}"],
        &[1, 2, 3, 4],
        &[],
    ),
    (
        "cfg_attr(test, ..), which gates an attribute and not the item",
        &["#[cfg_attr(test, derive(Debug))]", "struct Shipped;"],
        &[1, 2],
        &[],
    ),
];

fn shipped_line_numbers(lines: &[&str]) -> Vec<usize> {
    shipped_lines(&lines.join("\n"))
        .into_iter()
        .map(|(line_number, _)| line_number)
        .collect()
}

/// Shipped code is read wherever it sits: after a marked item of any kind,
/// and wherever a marker is only text. Fails for a skipper that drops too
/// much, from one that cuts at the first marker to one that drops everything.
#[test]
fn the_skipper_keeps_every_shipped_line() {
    for (case, lines, shipped, _) in SKIPPER_CASES {
        let kept = shipped_line_numbers(lines);
        let missing: Vec<_> = shipped.iter().filter(|line| !kept.contains(line)).collect();
        assert!(
            missing.is_empty(),
            "case {case:?}: shipped lines {missing:?} were dropped; kept {kept:?}"
        );
    }
}

/// Every marked item is dropped whole, attribute included. Fails for a
/// skipper that keeps test code, whether it ignores markers altogether or
/// stops short of an item's end.
#[test]
fn the_skipper_drops_every_test_only_item() {
    for (case, lines, _, test_only) in SKIPPER_CASES {
        let kept = shipped_line_numbers(lines);
        let leaked: Vec<_> = test_only
            .iter()
            .filter(|line| kept.contains(line))
            .collect();
        assert!(
            leaked.is_empty(),
            "case {case:?}: test-only lines {leaked:?} were read as shipped; kept {kept:?}"
        );
    }
}

/// The files an out-of-line test module loads are found by path: `name.rs`
/// beside the declaring file, `name/mod.rs`, files nested under either, and a
/// module declared from a non-`mod.rs` file, whose children live in a
/// directory named for it. Shipped modules declared beside them are not.
#[test]
fn out_of_line_test_modules_are_found_by_path() {
    let scratch = scratch_directory("test-module-files");
    let src = scratch.join("src");
    let write = |relative: &str, text: &str| {
        let path = src.join(relative);
        std::fs::create_dir_all(path.parent().expect("a planted file has a parent"))
            .expect("create a planted directory");
        std::fs::write(&path, text).expect("plant a source file");
        path
    };
    let lib = write(
        "lib.rs",
        "mod shipped;\n#[cfg(test)]\nmod flat_tests;\n#[cfg(all(test, unix))]\npub(crate) mod tree_tests;\n",
    );
    let shipped = write("shipped.rs", "#[cfg(test)]\nmod inner;\nmod public;\n");
    let flat = write("flat_tests.rs", "");
    let tree = write("tree_tests/mod.rs", "mod nested;\n");
    let nested = write("tree_tests/nested.rs", "");
    let inner = write("shipped/inner.rs", "");
    let public = write("shipped/public.rs", "");
    let files = vec![
        lib,
        shipped,
        flat.clone(),
        tree.clone(),
        nested.clone(),
        inner.clone(),
        public,
    ];

    let mut found = test_only_module_files(&files);
    let _ = std::fs::remove_dir_all(&scratch);
    found.sort();
    let mut expected = vec![flat, tree, nested, inner];
    expected.sort();
    assert_eq!(found, expected);
}

/// The smallest share of the workspace's non-blank source lines the skipper
/// may read as shipped. When this was set it read 68% (96,311 of 141,567
/// lines); a skipper that drops everything after the first test marker in
/// each file read 49.6%, and one that drops everything reads none, so both
/// fall below while ordinary churn in the test share stays above.
const MIN_SHIPPED_PERCENT: usize = 60;

/// The real tree, read whole: a skipper that has gone blind fails here even if
/// every planted case still happened to pass.
#[test]
fn the_skipper_reads_most_of_the_real_tree_as_shipped() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate lives in the workspace's crates directory");
    let mut files = Vec::new();
    let mut stack: Vec<PathBuf> = std::fs::read_dir(crates)
        .expect("list crates")
        .flatten()
        .map(|entry| entry.path().join("src"))
        .filter(|src| src.is_dir())
        .collect();
    while let Some(directory) = stack.pop() {
        for entry in std::fs::read_dir(&directory).expect("list a source directory") {
            let path = entry.expect("source entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path);
            }
        }
    }
    let test_files = test_only_module_files(&files);
    let mut total = 0;
    let mut shipped = 0;
    for file in &files {
        let source = std::fs::read_to_string(file).expect("read a source file");
        total += source
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count();
        if !test_files.contains(file) {
            shipped += shipped_lines(&source).len();
        }
    }
    assert!(
        total > 0 && shipped * 100 >= total * MIN_SHIPPED_PERCENT,
        "the skipper read {shipped} of {total} non-blank lines as shipped, under \
         {MIN_SHIPPED_PERCENT}%: it is dropping shipped code, and every scan built on \
         it would pass while reading only part of what it guards"
    );
}
