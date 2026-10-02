//! The module keeps one lease clock, and the compiler cannot say so.
//!
//! `SystemClock`'s epoch is fixed per instance, so two of them are not
//! comparable even though both produce a `MonoInstant`. A lease stamped by one
//! reads as long expired to the other, and the types agree at every step.
//!
//! That is not hypothetical here. Two consent sites built a fresh clock instead
//! of using the module's shared one: the ask settlement that MINTS a lease, and
//! `computer.open_target` itself. The result on a running module was that
//! `open_target` answered `already_held` with ten minutes remaining while every
//! computer action refused `no_lease` -- a remedy loop, since the refusal's
//! remedy was the call that had just succeeded. It stayed invisible while the module's
//! uptime was under the grant window and was total past it, which is why every
//! live probe had passed: each one ran minutes after a restart.
//!
//! A behavioural fence cannot reach this: reproducing it needs a module whose
//! uptime already exceeds a lease, and a freshly built `Planes` is always zero
//! seconds old. So the fence is structural -- exactly one construction site on
//! the production paths, the one that builds the module's own clock.

use std::path::{Path, PathBuf};

use crate::source_scan::{self, copy_tree, scratch_directory};

/// Construction sites allowed outside test code: the file, the site's exact
/// trimmed line, and the reason it exists. The line is matched exactly so that
/// the real-tree scan can insist on finding it: a site that is renamed or moved
/// fails the scan instead of leaving it to pass over nothing.
const ALLOWED: &[(&str, &str, &str)] = &[(
    "src/lib.rs",
    "let lease_clock = Arc::new(cerebellum_core::clock::SystemClock::new());",
    "the module's own lease clock, built once in Planes::new and shared by Arc",
)];

/// The fewest `.rs` files the real-tree walk may read and still pass. The crate
/// had 66 under `src` when this was set; the floor sits well below that so
/// ordinary churn never trips it, while a walk pointed at the wrong root, or
/// one that stopped descending, falls under it even if it still reaches the
/// file holding the allowed site.
const MIN_FILES_SCANNED: usize = 40;

#[test]
fn only_the_module_lease_clock_is_constructed_on_production_paths() {
    let scan = scan_crate(Path::new(env!("CARGO_MANIFEST_DIR")));

    assert!(
        scan.files_scanned >= MIN_FILES_SCANNED,
        "the scan read {} files under src, below the floor of {MIN_FILES_SCANNED}, \
         so it is not looking at the whole crate and a clean result proves nothing",
        scan.files_scanned
    );
    // The module's own clock has to be built somewhere, so not finding it means
    // the scan has gone blind or the site moved without this list following.
    assert!(
        scan.missing_allowed.is_empty(),
        "the allowed construction site was not found, so a clean result would \
         prove nothing. If it moved or was reworded on purpose, update ALLOWED:\n{}",
        scan.missing_allowed.join("\n")
    );
    // One message for both shapes, because the remedy is the same whether the
    // extra clock appeared in a new file or beside the allowed one.
    assert!(
        scan.violations.is_empty(),
        "a second clock cannot share the first one's epoch, so a lease it stamps \
         reads as expired everywhere else. Take the module's clock from \
         planes.lease_clock instead of building one here.\nallowed:\n{}\nfound:\n{}",
        ALLOWED
            .iter()
            .map(|(path, line, reason)| format!("  {path}: {line} ({reason})"))
            .collect::<Vec<_>>()
            .join("\n"),
        scan.violations
            .iter()
            .map(|site| format!("  {site}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// What one walk over a crate's `src` found.
struct TreeScan {
    files_scanned: usize,
    /// Allowed sites, as `path: line`, that the walk did not find.
    missing_allowed: Vec<String>,
    /// Forbidden construction sites, as `path:line: text`.
    violations: Vec<String>,
}

/// Walks every `.rs` file under `crate_root/src` and runs the detector on each,
/// with paths reported relative to `crate_root`.
fn scan_crate(crate_root: &Path) -> TreeScan {
    let mut scan = TreeScan {
        files_scanned: 0,
        missing_allowed: Vec::new(),
        violations: Vec::new(),
    };
    let mut allowed_found = vec![false; ALLOWED.len()];
    for file in rust_sources(&crate_root.join("src")) {
        scan.files_scanned += 1;
        let relative = file
            .strip_prefix(crate_root)
            .expect("sources live under the crate root")
            .to_string_lossy()
            .replace('\\', "/");
        let source = std::fs::read_to_string(&file).expect("read a crate source file");
        let sites = construction_sites(&source);
        for (found, (path, line, _)) in allowed_found.iter_mut().zip(ALLOWED) {
            if *path == relative && sites.iter().any(|(_, text)| text == line) {
                *found = true;
            }
        }
        scan.violations.extend(clock_violations(&relative, &source));
    }
    for (found, (path, line, _)) in allowed_found.iter().zip(ALLOWED) {
        if !found {
            scan.missing_allowed.push(format!("{path}: {line}"));
        }
    }
    scan
}

/// The clock construction sites in one file that the fence forbids, each as
/// `path:line: text`.
///
/// Each [`ALLOWED`] entry for this file excuses one production site whose line
/// matches it exactly; every other site is a violation, including a second
/// copy of the allowed line. Sites inside items marked `#[cfg(test)]` are never
/// counted.
fn clock_violations(path: &str, source: &str) -> Vec<String> {
    let mut allowances: Vec<&str> = ALLOWED
        .iter()
        .filter(|(allowed_path, _, _)| *allowed_path == path)
        .map(|(_, line, _)| *line)
        .collect();
    let mut violations = Vec::new();
    for (line_number, text) in construction_sites(source) {
        if let Some(index) = allowances.iter().position(|line| *line == text) {
            allowances.remove(index);
        } else {
            violations.push(format!("{path}:{line_number}: {text}"));
        }
    }
    violations
}

/// Every production line that names a `SystemClock` constructor, with its
/// 1-based number and trimmed text. A site split over several lines is
/// reported on the line where the type is named.
///
/// Matched on tokens rather than text, so layout cannot hide a call:
/// `SystemClock::new ()`, `SystemClock` and `::new()` on separate lines, and
/// the path-qualified `cerebellum_core::clock::SystemClock::new()` all count.
/// So does naming the constructor without calling it, as in
/// `.unwrap_or_else(SystemClock::new)`, which builds a clock all the same, and
/// `<SystemClock as Default>::default()`. A name the type is imported or
/// aliased under in the same file (`use ...::SystemClock as Clock;`,
/// `type Clock = ...::SystemClock;`) is matched like the type itself. Any
/// identifier ending in `SystemClock` counts, as it did when this was a plain
/// text match.
///
/// Comments and string literals are not parsed, so a mention in either counts
/// as a construction too. The effect is that the fence errs towards a false
/// alarm the author can reword, never towards a missed clock.
fn construction_sites(source: &str) -> Vec<(usize, String)> {
    let owned_lines = production_lines(source);
    let lines: Vec<(usize, &str)> = owned_lines
        .iter()
        .map(|(line_number, line)| (*line_number, line.as_str()))
        .collect();
    let tokens = source_scan::tokens(&lines);
    let aliases = clock_aliases(&tokens);
    let names_clock = |token: &str| token.ends_with("SystemClock") || aliases.contains(&token);
    let token_at = |index: usize| tokens.get(index).map(|(_, token)| *token);
    let is_constructor = |token: Option<&str>| matches!(token, Some("new" | "default"));
    let mut sites: Vec<(usize, String)> = Vec::new();
    for (index, &(line_number, token)) in tokens.iter().enumerate() {
        if !names_clock(token) {
            continue;
        }
        // `SystemClock::new`, or the trait-qualified
        // `<SystemClock as Default>::default`.
        let direct = token_at(index + 1) == Some("::") && is_constructor(token_at(index + 2));
        let qualified = token_at(index + 1) == Some("as")
            && token_at(index + 3) == Some(">")
            && token_at(index + 4) == Some("::")
            && is_constructor(token_at(index + 5));
        // One entry per line, as the line-based match gave, so the allowed
        // line is counted once however many constructors it names.
        if (direct || qualified) && sites.last().is_none_or(|(last, _)| *last != line_number) {
            let text = lines
                .iter()
                .find(|(number, _)| *number == line_number)
                .map(|(_, line)| line.trim().to_string())
                .unwrap_or_default();
            sites.push((line_number, text));
        }
    }
    sites
}

/// Names the clock type goes by in a file besides its own:
/// `use ...::SystemClock as Alias` (alone or inside a `{ ... }` group) and
/// `type Alias = ...::SystemClock;`.
fn clock_aliases<'a>(tokens: &[(usize, &'a str)]) -> Vec<&'a str> {
    let token_at = |index: usize| tokens.get(index).map(|(_, token)| *token);
    let mut aliases = Vec::new();
    for (index, &(_, token)) in tokens.iter().enumerate() {
        // A use item ends in `;`, `,` or `}`. The `>` of the trait-qualified
        // form `<SystemClock as Default>` is what tells that apart.
        if token.ends_with("SystemClock")
            && token_at(index + 1) == Some("as")
            && matches!(token_at(index + 3), Some(";" | "," | "}"))
        {
            aliases.extend(token_at(index + 2));
        }
        if token == "type" && token_at(index + 2) == Some("=") {
            let target: Vec<&str> = tokens[index + 3..]
                .iter()
                .map(|(_, token)| *token)
                .take_while(|token| *token != ";")
                .collect();
            let is_path = target.iter().all(|token| {
                *token == "::" || token.chars().all(|c| c.is_alphanumeric() || c == '_')
            });
            if is_path
                && target
                    .last()
                    .is_some_and(|last| last.ends_with("SystemClock"))
            {
                aliases.extend(token_at(index + 1));
            }
        }
    }
    aliases
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

/// Lines outside every item marked `#[cfg(test)]`, with their 1-based numbers.
/// Text that belongs to a test-only item is blanked, so a line shared with
/// shipped code keeps only the shipped part, and a line left empty is dropped.
///
/// Test code builds its own clocks deliberately and that is fine: a test owns
/// the whole timeline it measures. Each marked item is skipped over its own
/// extent, whatever kind of item it is (module, function, `impl`, `use`,
/// `const`, struct field), rather than everything after the first marker,
/// because this crate's largest file carries shipped code between test modules
/// and after test-only functions and fields.
///
/// Markers are found in code only: a `#[cfg(test)]` inside a comment or a
/// string literal marks nothing, and braces inside them do not count towards
/// an item's extent. Only the exact predicate `cfg(test)` marks an item
/// test-only. `all(test, ..)` would qualify too but is scanned as shipped code,
/// which errs towards a false alarm; `any(test, ..)` and `not(test)` code ships
/// and must be scanned.
fn production_lines(source: &str) -> Vec<(usize, String)> {
    let original: Vec<char> = source.chars().collect();
    let code = code_only(&original);
    let mut test_only = vec![false; code.len()];
    let mut index = 0;
    while index < code.len() {
        if let Some(after_attribute) = test_attribute_end(&code, index) {
            let end = item_end(&code, after_attribute);
            test_only[index..end].fill(true);
            index = end;
        } else {
            index += 1;
        }
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

/// If an outer attribute whose whole predicate is `cfg(test)` starts at
/// `index`, the position just after its closing `]`.
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
                    return (content == "[cfg(test)").then_some(position + 1);
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

/// Where the item an attribute applies to ends, scanning from just after the
/// attribute: after its body's closing brace (and a `;` that directly follows,
/// as in `use a::{b};`), after a `;` or a `,` at its own level (a statement,
/// a bodiless item, a field), or just before the bracket that closes the
/// enclosing scope.
///
/// Angle brackets are tracked only at the item's own level, so the commas in
/// `fn helper<A, B>(..)` do not end it. Every misjudgement here ends an item
/// early rather than late, which scans test code as shipped code and so errs
/// towards a false alarm, never a missed clock.
fn item_end(code: &[char], start: usize) -> usize {
    let mut depth = 0_i32;
    let mut angle = 0_i32;
    let mut previous = ' ';
    for (position, &c) in code.iter().enumerate().skip(start) {
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
            ',' if depth == 0 && angle == 0 => return position + 1,
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

/// The fence's positive control: planted constructions the detector must flag.
///
/// The real-tree test passes on a clean tree and on a detector that has gone
/// blind alike, so on its own a green result proves nothing. These cases fail
/// if the matching, the allowance or the `#[cfg(test)]` skipping stops finding
/// what it should.
#[test]
fn the_clock_detector_flags_every_planted_construction() {
    assert_flags(
        "a second SystemClock::new() beside the allowed one",
        "src/lib.rs",
        &[
            "fn planes_new() {",
            "    let lease_clock = Arc::new(cerebellum_core::clock::SystemClock::new());",
            "}",
            "fn consent() {",
            "    let clock = SystemClock::new();",
            "}",
        ],
        &[5],
    );
    // The allowance is for one site, so the allowed line written twice is a
    // second clock all the same.
    assert_flags(
        "the allowed line repeated in the allowed file",
        "src/lib.rs",
        &[
            "let lease_clock = Arc::new(cerebellum_core::clock::SystemClock::new());",
            "let lease_clock = Arc::new(cerebellum_core::clock::SystemClock::new());",
        ],
        &[2],
    );
    assert_flags(
        "the allowed line in a file with no allowance",
        "src/consent.rs",
        &["let lease_clock = Arc::new(cerebellum_core::clock::SystemClock::new());"],
        &[1],
    );
    assert_flags(
        "SystemClock::new() in a file with no allowance",
        "src/consent.rs",
        &["fn open() {", "    let clock = SystemClock::new();", "}"],
        &[2],
    );
    assert_flags(
        "SystemClock::default()",
        "src/consent.rs",
        &[
            "fn open() {",
            "    let clock = SystemClock::default();",
            "}",
        ],
        &[2],
    );
    // The shape of lib.rs: production code between two test modules. Only the
    // production site is flagged, and the second module is still skipped.
    assert_flags(
        "production code after a test module",
        "src/consent.rs",
        &[
            "#[cfg(test)]",
            "mod first_tests {",
            "    fn helper() {",
            "        let clock = SystemClock::new();",
            "    }",
            "}",
            "",
            "fn after_the_tests() {",
            "    let clock = SystemClock::new();",
            "}",
            "",
            "#[cfg(test)]",
            "mod second_tests {",
            "    fn helper() {",
            "        let clock = SystemClock::default();",
            "    }",
            "}",
        ],
        &[9],
    );
    // Neither of these builds a clock, but the scanner matches text on the line
    // and does not parse comments or strings, so both count. Pinned so that
    // changing that is a decision someone makes here, not a side effect.
    assert_flags(
        "a commented-out construction",
        "src/consent.rs",
        &["fn open() {", "    // let clock = SystemClock::new();", "}"],
        &[2],
    );
    assert_flags(
        "a construction named in a string literal",
        "src/consent.rs",
        &[
            "fn open() {",
            "    let hint = \"use planes.lease_clock, not SystemClock::default()\";",
            "}",
        ],
        &[2],
    );
    // Layout variants. The plain-text match this detector replaced missed
    // every one of these except the path-qualified call; each is kept here so
    // that a return to text matching fails by name.
    let variants: &[(&str, &[&str], &[usize])] = &[
        (
            "a space before the call's parentheses",
            &["let clock = SystemClock::new ();"],
            &[1],
        ),
        (
            "spaces around the path separator",
            &["let clock = SystemClock :: default();"],
            &[1],
        ),
        (
            "the path-qualified call",
            &["let clock = cerebellum_core::clock::SystemClock::new();"],
            &[1],
        ),
        (
            "a call split across lines",
            &[
                "fn open() {",
                "    let clock = cerebellum_core::clock::SystemClock",
                "        ::new();",
                "}",
            ],
            &[2],
        ),
        (
            "a use alias",
            &[
                "use cerebellum_core::clock::SystemClock as Clock;",
                "fn open() {",
                "    let clock = Clock::new();",
                "}",
            ],
            &[3],
        ),
        (
            "an alias inside a grouped use",
            &[
                "use cerebellum_core::clock::{",
                "    MonoInstant,",
                "    SystemClock as Clock,",
                "};",
                "fn open() { let clock = Clock::default(); }",
            ],
            &[5],
        ),
        (
            "a type alias",
            &[
                "type Clock = cerebellum_core::clock::SystemClock;",
                "fn open() { let clock = Clock::new(); }",
            ],
            &[2],
        ),
        (
            "the constructor named without a call",
            &["let clock = cached.unwrap_or_else(SystemClock::new);"],
            &[1],
        ),
        (
            "the trait-qualified default",
            &["let clock = <SystemClock as Default>::default();"],
            &[1],
        ),
    ];
    for (case, lines, expected) in variants {
        assert_flags(case, "src/consent.rs", lines, expected);
    }

    // Test markers on items other than a module, and markers that are not
    // code. In each, the shipped construction must be flagged and anything in
    // the marked item must not. The skipper this replaced cut from a marker
    // to the next `mod .. {` line, so it scanned a marked function or `impl`
    // as shipped code and then skipped the next shipped module whole.
    let marked: &[(&str, &[&str], &[usize])] = &[
        (
            "a marked fn, then a shipped module",
            &[
                "#[cfg(test)]",
                "fn helper() -> SystemClock {",
                "    SystemClock::new()",
                "}",
                "mod shipped {",
                "    fn open() { let clock = SystemClock::new(); }",
                "}",
            ],
            &[6],
        ),
        (
            "a marked fn with generic parameters",
            &[
                "#[cfg(test)]",
                "fn helper<A, B>(a: A, b: B) -> SystemClock {",
                "    SystemClock::new()",
                "}",
                "fn open() { let clock = SystemClock::new(); }",
            ],
            &[5],
        ),
        (
            "a marked const",
            &[
                "#[cfg(test)]",
                "const MAKE: fn() -> SystemClock = SystemClock::new;",
                "fn open() { let clock = SystemClock::default(); }",
            ],
            &[3],
        ),
        (
            "a marked use",
            &[
                "#[cfg(test)]",
                "use cerebellum_core::clock::{MonoInstant, SystemClock as TestClock};",
                "fn open() { let clock = SystemClock::new(); }",
            ],
            &[3],
        ),
        (
            "a marked impl",
            &[
                "#[cfg(test)]",
                "impl Planes {",
                "    fn test_clock() -> SystemClock { SystemClock::new() }",
                "}",
                "impl Planes {",
                "    fn clock() -> SystemClock { SystemClock::new() }",
                "}",
            ],
            &[6],
        ),
        (
            "a marked field in a struct literal",
            &[
                "fn build() -> Planes {",
                "    Planes {",
                "        #[cfg(test)]",
                "        test_clock: SystemClock::new(),",
                "        lease_clock: Arc::new(SystemClock::new()),",
                "    }",
                "}",
            ],
            &[5],
        ),
        (
            "a marker in a line comment",
            &[
                "// #[cfg(test)]",
                "mod shipped {",
                "    fn open() { let clock = SystemClock::new(); }",
                "}",
            ],
            &[3],
        ),
        (
            "a marker in a block comment",
            &["/* #[cfg(test)] */ fn open() { let clock = SystemClock::new(); }"],
            &[1],
        ),
        (
            "a marker in a string literal",
            &[
                "const EXAMPLE: &str = \"",
                "#[cfg(test)]",
                "mod tests {\";",
                "fn open() { let clock = SystemClock::new(); }",
            ],
            &[4],
        ),
        (
            "a brace in a string inside a test module",
            &[
                "#[cfg(test)]",
                "mod tests {",
                "    const OPEN: &str = \"{\";",
                "}",
                "fn open() { let clock = SystemClock::new(); }",
            ],
            &[5],
        ),
        // Only `cfg(test)` itself marks test-only code. `any(test, ..)` and
        // `not(test)` code ships; `all(test, ..)` does not, but is scanned as
        // shipped all the same, erring towards a false alarm. Pinned so that
        // treating any of these as test-only is a decision made here.
        (
            "a cfg(all(test, ..)) module",
            &[
                "#[cfg(all(test, feature = \"live\"))]",
                "mod live_tests {",
                "    fn helper() { let clock = SystemClock::new(); }",
                "}",
            ],
            &[3],
        ),
        (
            "a cfg(any(test, ..)) module",
            &[
                "#[cfg(any(test, feature = \"fixtures\"))]",
                "mod fixtures {",
                "    fn helper() { let clock = SystemClock::new(); }",
                "}",
            ],
            &[3],
        ),
        (
            "a cfg(not(test)) module",
            &[
                "#[cfg(not(test))]",
                "mod shipped {",
                "    fn open() { let clock = SystemClock::new(); }",
                "}",
            ],
            &[3],
        ),
    ];
    for (case, lines, expected) in marked {
        assert_flags(case, "src/consent.rs", lines, expected);
    }
}

/// The fence's negative control: planted source the detector must pass.
///
/// A detector that flags too much, such as every mention of the type or every
/// test module, tends to get loosened by hand until the tree passes. These
/// cases pin what is not a violation, so over-matching fails here by name.
#[test]
fn the_clock_detector_passes_every_planted_non_construction() {
    assert_flags(
        "the allowed site in the allowed file",
        "src/lib.rs",
        &[
            "fn planes_new() {",
            "    let lease_clock = Arc::new(cerebellum_core::clock::SystemClock::new());",
            "}",
        ],
        &[],
    );
    assert_flags(
        "a site inside a #[cfg(test)] module",
        "src/consent.rs",
        &[
            "#[cfg(test)]",
            "mod tests {",
            "    fn helper() {",
            "        let clock = SystemClock::new();",
            "        let other = SystemClock::default();",
            "    }",
            "}",
        ],
        &[],
    );
    assert_flags(
        "code that names the clock type or uses the shared clock",
        "src/consent.rs",
        &[
            "use cerebellum_core::clock::SystemClock;",
            "fn with_clock(clock: Arc<SystemClock>) -> Self {",
            "    let shared = Arc::clone(&planes.lease_clock);",
            "    let fake = MockClock::new();",
            "    let now = shared.now();",
            "}",
        ],
        &[],
    );
    // An alias is matched only where it is declared, and only as an exact
    // name: other clocks ending in the alias's text are not the system clock,
    // and the trait-qualified form is not an alias declaration.
    assert_flags(
        "other clocks beside an alias, and non-constructor calls",
        "src/consent.rs",
        &[
            "use cerebellum_core::clock::SystemClock as Clock;",
            "fn open(shared: &SystemClock) {",
            "    let fake = MockClock::new();",
            "    let now = <SystemClock as Clock>::now(shared);",
            "    let later = SystemClock::now(shared);",
            "    let plain = Clock::now(shared);",
            "}",
        ],
        &[],
    );
}

/// The walk's control: the real-tree scan's own walk, run over a copy of this
/// crate's `src` with one violating file planted two directories down.
///
/// The snippet controls exercise the detector on text handed to it, and the
/// premise check only proves the walk reaches `src/lib.rs`. Neither notices a
/// walk that stops descending into module directories or reads the wrong file
/// extension; this does.
#[test]
fn the_tree_walk_reports_a_planted_file_in_a_nested_module() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let scratch = scratch_directory("lease-clock-walk");
    copy_tree(&crate_root.join("src"), &scratch.join("src"));
    let nested = scratch.join("src/planted/deeper");
    std::fs::create_dir_all(&nested).expect("create the planted module directory");
    let planted = "pub fn second() { let _ = SystemClock::new(); }\n";
    std::fs::write(nested.join("second_clock.rs"), planted).expect("plant the violation");
    // The same text in a file that is not Rust source must not be read.
    std::fs::write(nested.join("second_clock.txt"), planted).expect("plant the decoy");

    let scan = scan_crate(&scratch);
    let _ = std::fs::remove_dir_all(&scratch);

    assert_eq!(
        scan.violations,
        ["src/planted/deeper/second_clock.rs:1: pub fn second() { let _ = SystemClock::new(); }"],
        "the walk must report the planted .rs file by path, and only it"
    );
    assert!(
        scan.missing_allowed.is_empty(),
        "the copied tree still holds the allowed site, so the walk must find it: {:?}",
        scan.missing_allowed
    );
}

/// Runs the detector over planted lines and asserts exactly `expected` (1-based
/// line numbers) are flagged.
fn assert_flags(case: &str, path: &str, lines: &[&str], expected: &[usize]) {
    let violations = clock_violations(path, &lines.join("\n"));
    let flagged: Vec<usize> = violations
        .iter()
        .map(|violation| {
            violation
                .split(':')
                .nth(1)
                .and_then(|number| number.parse().ok())
                .expect("a violation reads path:line: text")
        })
        .collect();
    assert_eq!(
        flagged, expected,
        "case {case:?}: the detector flagged the wrong lines: {violations:?}"
    );
}
