#!/usr/bin/env python3
"""Exercise the source-tree fence through the same CLI used by the gates."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


CHECK = Path(__file__).with_name("check-mutation-tree.py")


class MutationTreeTests(unittest.TestCase):
    def check(self, source, old="guard()", new="true", *, scope=None, edits=None, extra_source=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "mutations.d").mkdir()
            (root / "guard.rs").write_bytes(source.encode())
            if extra_source is not None:
                extra = root / "crates/other/src/lib.rs"
                extra.parent.mkdir(parents=True)
                extra.write_text(extra_source)
            row = '[control.scope]\nafter = "fn guarded() {"\nbefore = "\\n}"\n' if scope else ""
            if edits:
                anchors = "edits = [" + ",".join(
                    "{file = \"guard.rs\", old = " + json.dumps(a) + ", new = " + json.dumps(b) + "}"
                    for a, b in edits
                ) + "]\n"
            else:
                anchors = f'file = "guard.rs"\nold = {json.dumps(old)}\nnew = {json.dumps(new)}\n'
            (root / "mutations.d/guard.toml").write_text(
                '[[control]]\nid = "guard"\n' + anchors + row
            )
            return subprocess.run(
                [sys.executable, str(CHECK)], cwd=root, text=True, capture_output=True
            )

    def test_clean_source_passes(self):
        result = self.check("guard()")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("1 controls", result.stdout)

    def test_removed_guard_is_rejected(self):
        result = self.check("true")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("guard.toml:guard", result.stderr)

    def test_insertion_retaining_original_anchor_is_rejected(self):
        result = self.check("println!(); guard()", new="println!(); guard()")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("replacement containing the original", result.stderr)

    def test_manual_marker_is_rejected(self):
        result = self.check("guard() // NON-VACUITY BREAK")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("manual mutation marker", result.stderr)

    def test_marker_outside_catalogue_targets_is_rejected(self):
        result = self.check("guard()", extra_source="// NON-VACUITY BREAK")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("crates/other/src/lib.rs", result.stderr)

    def test_scope_ignores_other_functions(self):
        result = self.check("fn guarded() {guard()\n}\nfn other() {guard()}", scope=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_scope_is_rejected(self):
        result = self.check("guard()", scope=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("scope.after", result.stderr)

    def test_missing_scope_end_is_rejected(self):
        result = self.check("fn guarded() {guard()", scope=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("scope.before", result.stderr)

    def test_duplicate_anchor_is_rejected(self):
        result = self.check("guard(); guard()")
        self.assertNotEqual(result.returncode, 0)

    def test_noop_edit_is_rejected(self):
        result = self.check("guard()", new="guard()")
        self.assertNotEqual(result.returncode, 0)

    def test_unrelated_replacement_outside_scope_is_allowed(self):
        result = self.check(
            "fn guarded() {guard()\n}\nfn other() {println!(); guard()}",
            new="println!(); guard()", scope=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_empty_catalogue_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "mutations.d").mkdir()
            (root / "mutations.d/settings.toml").write_text("prebuild = []\n")
            result = subprocess.run([sys.executable, str(CHECK)], cwd=root, capture_output=True)
            self.assertNotEqual(result.returncode, 0)

    def test_invalid_catalogue_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "mutations.d").mkdir()
            (root / "mutations.d/bad.toml").write_text("[[control\n")
            result = subprocess.run([sys.executable, str(CHECK)], cwd=root, text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("bad.toml", result.stderr)

    def test_crlf_source_supports_multiline_anchors(self):
        result = self.check("guard()\r\nnext()", old="guard()\nnext()")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_sequential_edits_are_simulated_without_writing(self):
        result = self.check("guard()", edits=[("guard()", "intermediate()"), ("intermediate()", "true")])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_completed_sequential_mutant_is_rejected(self):
        result = self.check("true", edits=[("guard()", "intermediate()"), ("intermediate()", "true")])
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
