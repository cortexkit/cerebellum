#!/usr/bin/env python3
"""Select strict-check rows, conservatively falling back on catalogue shape changes."""
import json
from pathlib import Path
import subprocess
import sys
import tomllib
import unittest


def select_rows(previous, current, changed):
    if previous.keys() != current.keys():
        return None
    ids = [row.get("id") for doc in current.values() for row in doc.get("control", [])]
    # Duplicate identities are catalogue-wide errors, even when one copy is
    # unchanged. Let the runner diagnose them against the original catalogue.
    if len(ids) != len(set(ids)):
        return None
    selected = []
    for name, document in current.items():
        old = previous[name]
        # Shared setup and new root keys can change how every row is interpreted.
        if ({k: v for k, v in old.items() if k != "control"}
                != {k: v for k, v in document.items() if k != "control"}):
            return None
        old_rows = old.get("control", [])
        for row in document.get("control", []):
            anchors = {row.get("file"), row.get("test_file")}
            anchors.update(edit.get("file") for edit in row.get("edits", []))
            if row not in old_rows or anchors.intersection(changed):
                selected.append(row)
    return selected


def toml_value(value):
    # Inline tables retain all row fields, including fields the pinned runner
    # may reject. Do not reconstruct a permissive subset of its schema here.
    if isinstance(value, dict):
        return "{ " + ", ".join(f"{json.dumps(k)} = {toml_value(v)}" for k, v in value.items()) + " }"
    if isinstance(value, list):
        return "[" + ", ".join(map(toml_value, value)) + "]"
    if isinstance(value, (str, bool, int, float)):
        return json.dumps(value, ensure_ascii=False)
    raise ValueError(f"unsupported TOML value: {type(value).__name__}")


def catalogue_text(current, rows):
    settings = {}
    for document in current.values():
        for key, value in document.items():
            if key != "control":
                if key in settings:
                    raise ValueError(f"shared catalogue setting repeated: {key}")
                settings[key] = value
    lines = [f"{json.dumps(k)} = {toml_value(v)}" for k, v in settings.items()]
    for row in rows:
        lines.append("\n[[control]]")
        lines.extend(f"{json.dumps(k)} = {toml_value(v)}" for k, v in row.items())
    return "\n".join(lines) + "\n"


def git(*args):
    return subprocess.check_output(["git", *args])


def plan(base, destination):
    git("rev-parse", "--verify", f"{base}^{{commit}}")
    changed = set(git("diff", "--name-only", "--no-renames", "-z", base).decode().split("\0"))
    changed.update(git("ls-files", "--others", "--exclude-standard", "-z").decode().split("\0"))
    names = sorted(path.as_posix() for path in Path("mutations.d").glob("*.toml") if not path.name.startswith("."))
    old_names = git("ls-tree", "-r", "--name-only", base, "--", "mutations.d").decode().splitlines()
    if names != old_names or not names:
        return "full"
    try:
        current = {name: tomllib.loads(Path(name).read_text()) for name in names}
        previous = {name: tomllib.loads(git("show", f"{base}:{name}").decode()) for name in old_names}
        rows = select_rows(previous, current, changed)
        if rows is None:
            return "full"
        text = catalogue_text(current, rows)
        # Refuse to hand the runner a lossy serialization of the selected rows.
        if tomllib.loads(text).get("control", []) != rows:
            return "full"
    except (ValueError, TypeError, KeyError, AttributeError):
        return "full"
    Path(destination).write_text(text)
    return f"scoped {len(rows)}"


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.row = {"id": "unchanged", "file": "src/a.rs", "old": "yes", "new": "no"}
        self.previous = {"rows.toml": {"control": [self.row]}}

    def test_added_edited_and_anchored_rows_are_selected(self):
        edited = dict(self.row, new="different")
        added = dict(self.row, id="added", file="src/b.rs")
        current = {"rows.toml": {"control": [edited, added]}}
        self.assertEqual(select_rows(self.previous, current, set()), [edited, added])
        self.assertEqual(select_rows(self.previous, self.previous, {"src/a.rs"}), [self.row])

    def test_test_file_and_multi_edit_anchors_are_selected(self):
        row = dict(self.row, test_file="tests/a.rs", edits=[{"file": "src/b.rs"}])
        document = {"rows.toml": {"control": [row]}}
        for path in ("tests/a.rs", "src/b.rs"):
            self.assertEqual(select_rows(document, document, {path}), [row])

    def test_unrelated_changes_do_not_select_rows(self):
        self.assertEqual(select_rows(self.previous, self.previous, {"README.md"}), [])

    def test_catalogue_shape_changes_require_full_check(self):
        self.assertIsNone(select_rows(self.previous, {}, set()))
        self.assertIsNone(select_rows(self.previous, {"rows.toml": dict(self.previous["rows.toml"], prebuild=[])}, set()))

    def test_identical_duplicate_rows_require_full_check(self):
        duplicate = {"rows.toml": {"control": [self.row, self.row]}}
        self.assertIsNone(select_rows(self.previous, duplicate, set()))

    def test_planted_invalid_row_is_preserved_for_strict_check(self):
        invalid = dict(self.row, id="invalid", runner="command", command=["true"], expect_red=["missing_test"])
        current = {"rows.toml": {"control": [self.row, invalid]}}
        selected = select_rows(self.previous, current, set())
        self.assertEqual(selected, [invalid])
        self.assertEqual(tomllib.loads(catalogue_text(current, selected))["control"], [invalid])


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        unittest.main(argv=[sys.argv[0]], verbosity=2)
    else:
        print(plan(*sys.argv[1:]))
