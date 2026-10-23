#!/usr/bin/env python3
"""Check platform coverage and identify edits that need test-name validation."""
from pathlib import Path
import sys
import tomllib
import unittest


def documents(catalogue):
    paths = sorted(Path(catalogue).glob("*.toml"))
    if not paths:
        raise ValueError(f"no catalogue files in {catalogue}")
    return [tomllib.loads(path.read_text()) for path in paths if not path.name.startswith(".")]


def uncovered_rows(docs):
    return [row.get("id", "<missing id>") for doc in docs for row in doc.get("control", [])
            if "platforms" in row and (not isinstance(row["platforms"], list)
                                      or not {"linux", "macos"}.intersection(row["platforms"]))]


def affected(docs, changed):
    if any(path.startswith("mutations.d/") for path in changed):
        return True
    for doc in docs:
        for row in doc.get("control", []):
            anchors = {row.get("file"), row.get("test_file")}
            anchors.update(edit.get("file") for edit in row.get("edits", []))
            if anchors.intersection(changed):
                return True
    return False


class CatalogueTests(unittest.TestCase):
    def test_platform_union_covers_implicit_and_explicit_rows(self):
        docs = [{"control": [{"id": str(i), **fields} for i, fields in enumerate([
            {}, {"platforms": ["linux"]}, {"platforms": ["macos"]},
            {"platforms": ["windows", "linux"]}])]}]
        self.assertEqual(uncovered_rows(docs), [])

    def test_windows_only_empty_and_invalid_platforms_are_uncovered(self):
        for platforms in (["windows"], [], "linux"):
            self.assertEqual(uncovered_rows([{"control": [{"id": "uncovered", "platforms": platforms}]}]),
                             ["uncovered"])

    def test_catalogue_and_all_anchor_paths_trigger_name_checks(self):
        docs = [{"control": [{"file": "src/a.rs", "test_file": "tests/a.rs",
                              "edits": [{"file": "src/b.rs"}]}]}]
        for path in ("mutations.d/new.toml", "src/a.rs", "tests/a.rs", "src/b.rs"):
            self.assertTrue(affected(docs, {path}))
        self.assertFalse(affected(docs, {"README.md"}))


def main():
    mode, catalogue = sys.argv[1:]
    docs = documents(catalogue)
    if mode == "affected":
        return 0 if affected(docs, set(sys.stdin.read().splitlines())) else 1
    if mode != "coverage":
        raise ValueError(f"unknown mode: {mode}")
    uncovered = uncovered_rows(docs)
    if uncovered:
        raise ValueError("rows not covered by linux or macos: " + ", ".join(uncovered))
    count = sum(len(doc.get("control", [])) for doc in docs)
    print(f"mutation platform coverage: {count} rows covered by linux/macos")
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        unittest.main(argv=[sys.argv[0]], verbosity=2)
    else:
        try:
            sys.exit(main())
        except (OSError, ValueError, TypeError) as error:
            print(f"mutation catalogue: {error}", file=sys.stderr)
            sys.exit(2)
