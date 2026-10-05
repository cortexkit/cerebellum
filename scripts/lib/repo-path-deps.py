#!/usr/bin/env python3
"""Refuse dependency paths that resolve outside the repository, including symlinks."""
import os
from pathlib import Path
import sys
import json
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch


def scan(root):
    root = root.resolve()
    manifests = []
    for directory, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in {".git", "target", "node_modules", ".venv"}]
        if "Cargo.toml" in files:
            manifests.append(Path(directory) / "Cargo.toml")
    if not manifests:
        raise ValueError("no Cargo.toml files scanned")
    violations = []

    def visit(value, manifest, keys=()):
        if not isinstance(value, dict):
            return
        for key, child in value.items():
            if key in {"dependencies", "dev-dependencies", "build-dependencies", "replace"} or (keys and keys[-1] == "patch"):
                for name, dep in child.items():
                    if isinstance(dep, dict) and "path" in dep:
                        resolved = (manifest.parent / dep["path"]).resolve()
                        if not resolved.is_relative_to(root):
                            violations.append(f"{manifest.relative_to(root)}: {'.'.join(keys + (key, name))} path {dep['path']!r} resolves outside repository")
            else:
                visit(child, manifest, keys + (key,))

    for manifest in sorted(manifests):
        with manifest.open("rb") as source:
            visit(tomllib.load(source), manifest)
    return len(manifests), violations


def check(root):
    root = root.resolve()
    manifests, violations = scan(root)
    # Cargo progress belongs on stderr, not in the JSON document on stdout.
    result = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
        cwd=root, stdout=subprocess.PIPE, text=True, check=True,
    )
    metadata = json.loads(result.stdout)
    packages = [p for p in metadata["packages"] if p["source"] is None]
    if not packages:
        raise ValueError("metadata listed zero sourceless packages")
    for package in packages:
        manifest = Path(package["manifest_path"]).resolve()
        if not manifest.is_relative_to(root):
            violations.append(f"sourceless package {package['name']} manifest {manifest} is outside repository")
    return manifests, len(packages), violations


class PathDependencyTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name) / "repo"
        self.root.mkdir()

    def manifest(self, text):
        (self.root / "Cargo.toml").write_text(text)

    def test_internal_paths_and_comments_are_allowed(self):
        self.manifest('# path = "../outside"\n[dependencies]\nlocal = { path = "crates/local" }\n[[bin]]\nname = "tool"\npath = "../not-a-dependency.rs"\n')
        self.assertEqual(scan(self.root), (1, []))

    def test_planted_external_dependency_is_rejected(self):
        self.manifest('[dependencies]\nplanted = { path = "../outside" }\n')
        self.assertEqual(len(scan(self.root)[1]), 1)

    def test_target_workspace_and_build_dependencies_are_rejected(self):
        self.manifest('[workspace.dependencies]\na = { path = "../a" }\n[target.\'cfg(unix)\'.dev-dependencies]\nb = { path = "../b" }\n[build-dependencies.c]\npath = "../c"\n')
        self.assertEqual(len(scan(self.root)[1]), 3)

    def test_patch_and_replace_paths_are_rejected(self):
        self.manifest('[patch.crates-io]\na = { path = "../a" }\n[replace]\n"b:1.0.0" = { path = "../b" }\n')
        self.assertEqual(len(scan(self.root)[1]), 2)

    def test_symlink_escape_is_rejected(self):
        (self.root / "linked").symlink_to(self.root.parent, target_is_directory=True)
        self.manifest('[dependencies]\na = { path = "linked/outside" }\n')
        self.assertEqual(len(scan(self.root)[1]), 1)

    def cargo_workspace(self):
        (self.root / "src").mkdir()
        (self.root / "src/lib.rs").write_text("")
        return '[package]\nname = "guard-control"\nversion = "0.1.0"\nedition = "2021"\n'

    def outside_crate(self):
        outside = self.root.parent / "outside"
        (outside / "src").mkdir(parents=True)
        (outside / "src/lib.rs").write_text("")
        (outside / "Cargo.toml").write_text('[package]\nname = "outside-control"\nversion = "0.1.0"\n')

    def lock(self):
        subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=self.root, check=True)

    def test_metadata_declared_external_path_is_rejected(self):
        self.outside_crate()
        self.manifest(self.cargo_workspace() + '[dependencies]\noutside-control = { path = "../outside" }\n')
        self.lock()
        failures = check(self.root)[2]
        self.assertTrue(any("dependencies.outside-control path" in f for f in failures))

    def test_metadata_external_patch_is_rejected(self):
        self.outside_crate()
        self.manifest(self.cargo_workspace() + '[dependencies]\noutside-control = "=0.1.0"\n[patch.crates-io]\noutside-control = { path = "../outside" }\n')
        self.lock()
        failures = check(self.root)[2]
        self.assertTrue(any("sourceless package outside-control" in f for f in failures))

    def test_metadata_clean_workspace_passes(self):
        self.manifest(self.cargo_workspace())
        self.lock()
        self.assertEqual(check(self.root), (1, 1, []))

    def test_invalid_metadata_is_a_check_failure(self):
        self.manifest(self.cargo_workspace())
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "not JSON")):
            with self.assertRaises(json.JSONDecodeError):
                check(self.root)

    def test_zero_sourceless_packages_is_a_check_failure(self):
        self.manifest(self.cargo_workspace())
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, '{"packages": []}')):
            with self.assertRaisesRegex(ValueError, "zero sourceless"):
                check(self.root)

    def test_empty_scan_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "no Cargo.toml"):
            scan(self.root)


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        unittest.main(argv=[sys.argv[0]], verbosity=2)
    else:
        try:
            count, packages, failures = check(Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd())
        except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError) as error:
            print(f"repository-contained path dependencies: CHECK FAILED: {error}", file=sys.stderr)
            sys.exit(2)
        print(f"repository-contained path dependencies: scanned {count} manifests and {packages} sourceless packages")
        for failure in failures:
            print(f"repository-contained path dependencies: FAILED: {failure}", file=sys.stderr)
        sys.exit(bool(failures))
