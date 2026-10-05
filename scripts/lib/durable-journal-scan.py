#!/usr/bin/env python3
"""Find test code that builds something journaling to the operator's disk.

The journals, the computer audit and the browser profile registry resolve their
location from the data home (XDG_DATA_HOME, then HOME). That directory is
backed up and holds real browser profiles, and it is process-wide, so a test
cannot be pointed elsewhere without redirecting every test beside it. Tests
therefore opt into isolation at construction -- and this finds the ones that
did not.

Test code is found structurally, not by line matching:

  * every file under `crates/*/tests/` is test code;
  * under `crates/*/src/`, an item carrying a test-enabling attribute is test
    code: `#[cfg(test)]` (also inside `all(..)`/`any(..)`, never under
    `not(..)`), `#[test]`, or a path ending in `test` such as `#[tokio::test]`;
    an inner `#![cfg(test)]` makes the rest of its file test code;
  * a function whose name contains `for_test` is test support, compiled into
    the library only so integration tests can call it;
  * a module declared out of line under such an attribute (`#[cfg(test)]
    mod tests;`) makes its file, and every module that file declares, test code.

Source is tokenized first, so comments and string literals never match and
line breaks or spacing inside `Planes :: new (` cannot hide one.

Output: one `path:line: <construct>` per offender on stderr, then a summary
line naming how many files were scanned. Exit status:

  0  no offender, and something was scanned
  1  at least one offender
  2  nothing to scan, no test code found, or an out-of-line test module whose
     file could not be found -- each is a scan that would otherwise pass
     having looked at nothing

Usage:
  durable-journal-scan.py [ROOT]      ROOT defaults to the current directory
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Constructs that write to the operator's data home. Each is a token sequence,
# `::` being two `:` tokens.
OFFENDERS: List[Tuple[str, List[str]]] = [
    # The plane constructor that journals durably. `Planes::new` journals in
    # memory, so it isn't listed.
    (
        "Planes::with_browser_config(",
        ["Planes", ":", ":", "with_browser_config", "("],
    ),
    # Naming durability outright, whatever it is passed to.
    ("JournalPersistence::Durable", ["JournalPersistence", ":", ":", "Durable"]),
    # Openers that always take the operator's own files: the computer audit,
    # the launch journal (whose startup recovery can kill a live browser and
    # move profile custody), and the profile registry of real browser profiles.
    ("production_audit(", ["production_audit", "("]),
    (
        "DurableLaunchJournal::open_filesystem(",
        ["DurableLaunchJournal", ":", ":", "open_filesystem", "("],
    ),
    ("production_profile_lifecycle(", ["production_profile_lifecycle", "("]),
    # Cerebellum's call records (one entry per tool call that carried a
    # call_key), kept in the operator's backed-up journal directory.
    (
        "CallRecords::open_durable(",
        ["CallRecords", ":", ":", "open_durable", "("],
    ),
    # The format floor chosen from the process's own data home, which in a
    # test is the operator's: any store it names under that home would raise
    # the operator's floor file. Tests choose with `governing_under` and a
    # scratch data home, or name a scratch floor file outright.
    (
        "FormatFloor::governing(",
        ["FormatFloor", ":", ":", "governing", "("],
    ),
]

FIRST_TOKENS = {sequence[0] for _, sequence in OFFENDERS}

# Test files that must build a durable plane, each with the reason. Empty: an
# entry here is a test that writes to the operator's backed-up data home.
ALLOWED: Dict[str, str] = {}

Token = Tuple[str, str, int]  # (kind, text, line); kind is "ident", "punct", "lit"


def tokenize(source: str) -> List[Token]:
    tokens: List[Token] = []
    i, line, n = 0, 1, len(source)
    while i < n:
        c = source[i]
        if c == "\n":
            line += 1
            i += 1
        elif c.isspace():
            i += 1
        elif source.startswith("//", i):
            while i < n and source[i] != "\n":
                i += 1
        elif source.startswith("/*", i):
            depth, i = 1, i + 2
            while i < n and depth:
                if source.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif source.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    line += source[i] == "\n"
                    i += 1
        elif c.isalpha() or c == "_":
            start = i
            while i < n and (source[i].isalnum() or source[i] == "_"):
                i += 1
            word = source[start:i]
            # A raw or byte string starts like an identifier: r"..", r#".."#,
            # b"..", br#".."#.
            if word in ("r", "br", "b", "c", "cr") and i < n and source[i] in "\"#":
                if word.endswith("r"):
                    hashes = 0
                    while i < n and source[i] == "#":
                        hashes, i = hashes + 1, i + 1
                    if i < n and source[i] == '"':
                        close = '"' + "#" * hashes
                        end = source.find(close, i + 1)
                        end = n if end < 0 else end + len(close)
                        tokens.append(("lit", source[i + 1 : end - len(close)], line))
                        line += source.count("\n", i, end)
                        i = end
                        continue
                    # `r#ident` is a raw identifier, not a string.
                    start = i
                    while i < n and (source[i].isalnum() or source[i] == "_"):
                        i += 1
                    tokens.append(("ident", source[start:i], line))
                    continue
                if source[i] == '"':
                    start_line = line
                    end, line = _skip_quoted(source, i, line, '"')
                    tokens.append(("lit", source[i + 1 : end - 1], start_line))
                    i = end
                    continue
            tokens.append(("ident", word, line))
        elif c.isdigit():
            while i < n and (source[i].isalnum() or source[i] in "_."):
                # `0..10` is a range, not a number with two points.
                if source[i] == "." and source.startswith("..", i):
                    break
                i += 1
            tokens.append(("lit", "", line))
        elif c == '"':
            start_line = line
            end, line = _skip_quoted(source, i, line, '"')
            # Kept so a `#[path = ".."]` value can be read; never matched.
            tokens.append(("lit", source[i + 1 : end - 1], start_line))
            i = end
        elif c == "'":
            # A character literal ('a', '\n', '\u{1F600}') or a lifetime ('a).
            if i + 1 < n and source[i + 1] == "\\":
                i, line = _skip_quoted(source, i, line, "'")
                tokens.append(("lit", "", line))
            elif i + 2 < n and source[i + 2] == "'":
                i += 3
                tokens.append(("lit", "", line))
            else:
                tokens.append(("punct", "'", line))
                i += 1
        else:
            tokens.append(("punct", c, line))
            i += 1
    return tokens


def _skip_quoted(source: str, i: int, line: int, quote: str) -> Tuple[int, int]:
    i += 1
    n = len(source)
    while i < n and source[i] != quote:
        if source[i] == "\\":
            i += 1
        if i < n and source[i] == "\n":
            line += 1
        i += 1
    return i + 1, line


def _matching(tokens: List[Token], open_index: int) -> int:
    """Index of the bracket closing the one at `open_index`."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    opener = tokens[open_index][1]
    closer, depth = pairs[opener], 0
    for index in range(open_index, len(tokens)):
        text = tokens[index][1]
        if tokens[index][0] != "punct":
            continue
        if text == opener:
            depth += 1
        elif text == closer:
            depth -= 1
            if depth == 0:
                return index
    return len(tokens) - 1


def _cfg_enables_test(predicate: List[Token]) -> bool:
    """Whether a cfg predicate can hold only in a test build, read loosely:
    `test` anywhere except under `not(..)`."""
    depth_in_not: List[int] = []
    depth = 0
    for index, (kind, text, _) in enumerate(predicate):
        if kind == "punct" and text == "(":
            depth += 1
        elif kind == "punct" and text == ")":
            if depth_in_not and depth_in_not[-1] == depth:
                depth_in_not.pop()
            depth -= 1
        elif kind == "ident" and text == "not":
            depth_in_not.append(depth + 1)
        elif kind == "ident" and text == "test" and not depth_in_not:
            following = predicate[index + 1][1] if index + 1 < len(predicate) else ""
            if following != "=":
                return True
    return False


def _attribute_enables_test(content: List[Token]) -> bool:
    if not content:
        return False
    if content[0][1] == "cfg" and len(content) > 1 and content[1][1] == "(":
        return _cfg_enables_test(content[2:-1])
    # `#[test]`, `#[tokio::test]`, `#[tokio::test(flavor = ..)]`.
    path: List[str] = []
    for kind, text, _ in content:
        if kind == "punct" and text == "(":
            break
        if kind == "ident":
            path.append(text)
    return bool(path) and path[-1] == "test"


class FileScan:
    def __init__(self, path: Path, tokens: List[Token]):
        self.path = path
        self.tokens = tokens
        # Half-open token ranges that are test code.
        self.regions: List[Tuple[int, int]] = []
        # Out-of-line modules: (name, #[path] value or None, declared in test code).
        self.modules: List[Tuple[str, Optional[str], bool]] = []


def scan_structure(path: Path) -> FileScan:
    tokens = tokenize(path.read_text(encoding="utf-8", errors="replace"))
    scan = FileScan(path, tokens)
    i = 0
    pending_test_start: Optional[int] = None
    pending_path: Optional[str] = None
    while i < len(tokens):
        kind, text, _ = tokens[i]
        if kind == "punct" and text == "#":
            inner = i + 1 < len(tokens) and tokens[i + 1][1] == "!"
            bracket = i + 2 if inner else i + 1
            if bracket < len(tokens) and tokens[bracket][1] == "[":
                close = _matching(tokens, bracket)
                content = tokens[bracket + 1 : close]
                if _attribute_enables_test(content):
                    if inner:
                        scan.regions.append((i, len(tokens)))
                    elif pending_test_start is None:
                        pending_test_start = i
                if (
                    len(content) >= 3
                    and content[0][1] == "path"
                    and content[1][1] == "="
                ):
                    pending_path = content[2][1] if content[2][0] == "lit" else None
                i = close + 1
                continue
        # A function named for tests (`handle_tool_request_for_test`) is
        # test support even where it is compiled into the library so that
        # integration tests can call it.
        if (
            pending_test_start is None
            and kind == "ident"
            and text == "fn"
            and i + 1 < len(tokens)
            and "for_test" in tokens[i + 1][1]
        ):
            scan.regions.append((i, _item_end(tokens, i) + 1))
        if kind == "ident" and text == "mod" and i + 2 < len(tokens):
            name, after = tokens[i + 1][1], tokens[i + 2][1]
            if after == ";":
                in_test = pending_test_start is not None or scan_in_regions(scan, i)
                scan.modules.append((name, pending_path, in_test))
        if pending_test_start is not None:
            end = _item_end(tokens, i)
            scan.regions.append((pending_test_start, end + 1))
            pending_test_start = None
            # Keep walking inside the item: a nested out-of-line module
            # declaration must still be recorded.
            i += 1
            continue
        if kind == "punct" and text in (";", "{", "}"):
            pending_path = None
        i += 1
    return scan


def scan_in_regions(scan: FileScan, index: int) -> bool:
    return any(start <= index < end for start, end in scan.regions)


def _item_end(tokens: List[Token], start: int) -> int:
    """The last token of the item beginning at `start`: its closing brace, or
    the `;` ending a bodiless item such as `mod tests;`."""
    depth = 0
    for index in range(start, len(tokens)):
        kind, text, _ = tokens[index]
        if kind != "punct":
            continue
        if text in "([":
            depth += 1
        elif text in ")]":
            depth -= 1
        elif text == ";" and depth == 0:
            return index
        elif text == "{" and depth == 0:
            return _matching(tokens, index)
    return len(tokens) - 1


def module_file(parent: Path, name: str, explicit: Optional[str]) -> Optional[Path]:
    if explicit is not None:
        candidate = parent.parent / explicit
        return candidate if candidate.is_file() else None
    if parent.name in ("mod.rs", "lib.rs", "main.rs"):
        base = parent.parent
    else:
        base = parent.parent / parent.stem
    for candidate in (base / f"{name}.rs", base / name / "mod.rs"):
        if candidate.is_file():
            return candidate
    return None


def offenders_in(tokens: List[Token], ranges: List[Tuple[int, int]]) -> List[Tuple[int, str]]:
    found: List[Tuple[int, str]] = []
    # Test items nest (a `#[test]` inside a `#[cfg(test)]` module), so the
    # ranges are merged first rather than scanning shared tokens twice.
    merged: List[Tuple[int, int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    for start, end in merged:
        for index in range(start, min(end, len(tokens))):
            if tokens[index][1] not in FIRST_TOKENS:
                continue
            for label, sequence in OFFENDERS:
                window = tokens[index : index + len(sequence)]
                if len(window) == len(sequence) and all(
                    token[0] != "lit" and token[1] == expected
                    for token, expected in zip(window, sequence)
                ):
                    found.append((tokens[index][2], label))
    return sorted(set(found))


def main(argv: List[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path(".")
    integration = sorted(root.glob("crates/*/tests/**/*.rs"))
    sources = sorted(root.glob("crates/*/src/**/*.rs"))

    offences: List[str] = []
    problems: List[str] = []

    def report(path: Path, found: List[Tuple[int, str]]) -> None:
        relative = path.relative_to(root).as_posix()
        if relative in ALLOWED:
            return
        for line, label in found:
            offences.append(f"{relative}:{line}: {label}")

    for path in integration:
        tokens = tokenize(path.read_text(encoding="utf-8", errors="replace"))
        report(path, offenders_in(tokens, [(0, len(tokens))]))

    scans = {path: scan_structure(path) for path in sources}
    whole_test_files: Set[Path] = set()
    pending = []
    for scan in scans.values():
        for name, explicit, in_test in scan.modules:
            if in_test:
                pending.append((scan.path, name, explicit))
    while pending:
        parent, name, explicit = pending.pop()
        child = module_file(parent, name, explicit)
        if child is None:
            problems.append(
                f"{parent.relative_to(root).as_posix()}: test module `{name}` has no file"
            )
            continue
        child = child.resolve()
        matched = next((p for p in scans if p.resolve() == child), None)
        if matched is None or matched in whole_test_files:
            continue
        whole_test_files.add(matched)
        for grand_name, grand_explicit, _ in scans[matched].modules:
            pending.append((matched, grand_name, grand_explicit))

    region_count = 0
    for path, scan in scans.items():
        if path in whole_test_files:
            report(path, offenders_in(scan.tokens, [(0, len(scan.tokens))]))
        else:
            region_count += len(scan.regions)
            report(path, offenders_in(scan.tokens, scan.regions))

    for offence in offences:
        print(offence, file=sys.stderr)
    for problem in problems:
        print(problem, file=sys.stderr)
    print(
        f"scanned {len(integration)} integration-test files and {len(sources)} "
        f"source files ({region_count} in-crate test items, "
        f"{len(whole_test_files)} whole test-module files)"
    )
    if problems:
        return 2
    if not integration or not sources or region_count + len(whole_test_files) == 0:
        print("nothing was scanned, so nothing was checked", file=sys.stderr)
        return 2
    return 1 if offences else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
