#!/usr/bin/env python3
"""Reject an interrupted catalogue edit without building or modifying source."""

from pathlib import Path
import sys
import tomllib


def region(text, scope):
    start, end = 0, len(text)
    if scope:
        after = scope["after"]
        if text.count(after) != 1:
            raise ValueError("scope.after must occur exactly once")
        start = text.index(after) + len(after)
        if "before" in scope:
            end = text.find(scope["before"], start)
            if end < 0:
                raise ValueError("scope.before is missing")
    return start, end


def check_row(root, row):
    edits = row.get("edits") or [
        {key: row[key] for key in ("file", "old", "new")}
    ]
    sources = {}
    for edit in edits:
        path = edit["file"]
        if path not in sources:
            # Catalogue anchors use LF. Reading CRLF source as text lets the
            # same anchors work on Windows without rewriting any source bytes.
            sources[path] = (root / path).read_text()
            if "NON-VACUITY BREAK" in sources[path]:
                raise ValueError(f"{path}: manual mutation marker is present")
        text = sources[path]
        start, end = region(text, row.get("scope"))
        scoped = text[start:end]
        old, new = edit["old"], edit["new"]
        if not old or old == new:
            raise ValueError(f"{path}: empty or no-op edit")
        if scoped.count(old) != 1:
            raise ValueError(f"{path}: original anchor must occur exactly once")
        # Insertion mutants can retain the complete old anchor. Merely checking
        # that anchor would bless, for example, a planted println before it.
        if old in new and new in scoped:
            raise ValueError(f"{path}: replacement containing the original is present")
        sources[path] = text[:start] + scoped.replace(old, new, 1) + text[end:]


def main(root):
    fragments = sorted(
        path for path in (root / "mutations.d").glob("*.toml")
        if not path.name.startswith(".")
    )
    if not fragments:
        print("mutation tree check: missing mutations.d catalogue", file=sys.stderr)
        return 1
    count, failures = 0, []
    # A manual proof may be interrupted before its new catalogue row is written.
    # Check its marker in Rust source even if no existing row names that file.
    for source in sorted((root / "crates").rglob("*.rs")):
        if any(part.startswith(".") for part in source.relative_to(root).parts):
            continue
        if "NON-VACUITY BREAK" in source.read_text():
            failures.append(f"{source.relative_to(root)}: manual mutation marker is present")
    for fragment in fragments:
        try:
            rows = tomllib.loads(fragment.read_text()).get("control", [])
        except (OSError, ValueError) as error:
            failures.append(f"{fragment.name}: {error}")
            continue
        for row in rows:
            count += 1
            try:
                check_row(root, row)
            except (OSError, KeyError, ValueError) as error:
                failures.append(f"{fragment.name}:{row.get('id', '<missing id>')}: {error}")
    if not count:
        failures.append("catalogue contains no controls")
    if failures:
        print("mutation tree check: source does not match the unmutated catalogue:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        print("Stop any replay and its children before restoring source. If this is an intentional guard edit, update its catalogue row.", file=sys.stderr)
        return 1
    print(f"mutation tree check: {count} controls have unmutated source anchors")
    return 0


if __name__ == "__main__":
    sys.exit(main(Path.cwd()))
