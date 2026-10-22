#!/usr/bin/env python3
"""Identify the input tree of each gate half without updating Git metadata."""
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys

PREFIX = "FAST GATE FINGERPRINT: "
LINE = re.compile(
    re.escape(PREFIX) + r"head=[0-9a-f]{40,64} base=[0-9a-f]{40,64} "
    r"diff=[0-9a-f]{64} untracked=[0-9a-f]{64}"
)


def git(root, *args):
    return subprocess.check_output(
        ["git", *args], cwd=root, env=dict(os.environ, GIT_OPTIONAL_LOCKS="0")
    )


def fingerprint(base, root=None):
    root = Path.cwd() if root is None else Path(root)
    head = git(root, "rev-parse", "--verify", "HEAD^{commit}").decode("ascii").strip()
    base = git(root, "rev-parse", "--verify", f"{base}^{{commit}}").decode("ascii").strip()
    # Capture bytes, not decoded patch text: binary changes and unusual path
    # bytes must participate too. Disable local diff helpers and rename settings.
    patch = git(root, "-c", "core.quotePath=true", "diff", "--binary", "--full-index",
                "--no-ext-diff", "--no-textconv", "--no-renames", "--no-color",
                "--src-prefix=a/", "--dst-prefix=b/", "--diff-algorithm=myers",
                "--no-indent-heuristic", "--unified=3", "--inter-hunk-context=0", "HEAD", "--")
    untracked = hashlib.sha256()
    names = git(root, "ls-files", "--others", "--exclude-standard", "-z").split(b"\0")
    for name in sorted(name for name in names if name):
        path = os.path.join(os.fsencode(root), name)
        mode = os.lstat(path).st_mode
        # Length framing makes names/content boundaries unambiguous, even with
        # embedded newlines. Hash a symlink's own bytes, never its outside target.
        untracked.update(struct.pack(">Q", len(name)))
        untracked.update(name)
        if stat.S_ISLNK(mode):
            content = os.readlink(path)
            untracked.update(b"L" + struct.pack(">Q", len(content)) + content)
        elif stat.S_ISREG(mode):
            with open(path, "rb") as source:
                size = os.fstat(source.fileno()).st_size
                untracked.update(b"F" + struct.pack(">Q", size))
                read = 0
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    untracked.update(chunk)
                    read += len(chunk)
                if read != size:
                    raise ValueError("untracked file changed while fingerprinting")
        else:
            raise ValueError("cannot fingerprint a non-file untracked entry")
    return (f"{PREFIX}head={head} base={base} diff={hashlib.sha256(patch).hexdigest()} "
            f"untracked={untracked.hexdigest()}")


def compare(linux_log, mac_log):
    reports = []
    for log in (linux_log, mac_log):
        reports.append([line for line in Path(log).read_text(errors="replace").splitlines()
                        if line.startswith(PREFIX)])
    valid = all(len(lines) == 1 and LINE.fullmatch(lines[0]) for lines in reports)
    if not valid or reports[0] != reports[1]:
        print("FAST GATE FAILED: missing, malformed, or mismatched tree fingerprints", file=sys.stderr)
        for label, lines in zip(("Linux", "Mac"), reports):
            print(f"{label} fingerprint: {' | '.join(lines) if lines else '<missing>'}", file=sys.stderr)
        return 1
    print("==> PASS: matching Linux/Mac tree fingerprints")
    return 0


def self_test():
    import tempfile
    import unittest

    class FingerprintTests(unittest.TestCase):
        def setUp(self):
            scratch = Path(os.environ.get("CARGO_TARGET_DIR", "target")) / "scratch"
            scratch.mkdir(parents=True, exist_ok=True)
            self.scratch = tempfile.TemporaryDirectory(dir=scratch)
            self.addCleanup(self.scratch.cleanup)
            self.root = Path(self.scratch.name).resolve()
            git(self.root, "init", "-q")
            git(self.root, "config", "user.name", "fast-gate-fixture")
            git(self.root, "config", "user.email", "fixture@example.invalid")
            (self.root / "tracked").write_bytes(b"\0original\xff")
            (self.root / ".gitignore").write_text("ignored/\n")
            git(self.root, "add", "tracked", ".gitignore")
            git(self.root, "-c", "commit.gpgsign=false", "commit", "-qm", "fixture")

        def test_head_base_and_binary_worktree_changes(self):
            before = fingerprint("HEAD", self.root)
            self.assertRegex(before, LINE)
            head = git(self.root, "rev-parse", "HEAD").decode().strip()
            self.assertIn(f"head={head} base={head}", before)
            (self.root / "tracked").write_bytes(b"\0different\xfe")
            after = fingerprint("HEAD", self.root)
            self.assertNotEqual(before.split("diff=")[1], after.split("diff=")[1])
            git(self.root, "add", "tracked")
            self.assertEqual(after, fingerprint("HEAD", self.root))

        def test_untracked_names_contents_and_ignored_files(self):
            before = fingerprint("HEAD", self.root)
            suffix = "é".encode() if sys.platform == "darwin" else b"\xff"
            name = os.fsencode(self.root) + b"/new\n" + suffix
            with open(name, "wb") as file:
                file.write(b"\0first")
            added = fingerprint("HEAD", self.root)
            self.assertNotEqual(before, added)
            with open(name, "wb") as file:
                file.write(b"\0other")
            changed = fingerprint("HEAD", self.root)
            self.assertNotEqual(added, changed)
            os.rename(name, name + b"renamed")
            renamed = fingerprint("HEAD", self.root)
            self.assertNotEqual(changed, renamed)
            (self.root / "ignored").mkdir()
            (self.root / "ignored" / "log").write_text("not an input")
            self.assertEqual(renamed, fingerprint("HEAD", self.root))

        def test_symlink_uses_link_bytes_and_git_index_is_unchanged(self):
            (self.root / "link").symlink_to("nonexistent-first")
            index = self.root / ".git" / "index"
            before = (index.read_bytes(), index.stat().st_mtime_ns)
            first = fingerprint("HEAD", self.root)
            self.assertEqual(before, (index.read_bytes(), index.stat().st_mtime_ns))
            (self.root / "link").unlink()
            (self.root / "link").symlink_to("nonexistent-other")
            self.assertNotEqual(first, fingerprint("HEAD", self.root))

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(FingerprintTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    try:
        if sys.argv[1:2] == ["--compare"]:
            sys.exit(compare(*sys.argv[2:]))
        elif sys.argv[1:] == ["--self-test"]:
            self_test()
        else:
            print(fingerprint(*sys.argv[1:]))
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"fast gate fingerprint: {error}", file=sys.stderr)
        sys.exit(2)
