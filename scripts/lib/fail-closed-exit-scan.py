#!/usr/bin/env python3
"""Require the shared fail-closed EXIT handler in nounset shell scripts."""

from pathlib import Path
import re
import shlex
import sys


COMMAND = re.compile(r"(?:^|[;&|])\s*(?:set|trap|source|\.)\s+")
SKIPPED = {"train-push.sh", "train-push-lock.test.sh"}


def shell_commands(text):
    # Read declarations, including semicolon-separated ones. Shell quoting keeps
    # a handler's commands together; comments cannot supply a protection marker.
    for line in text.replace("\\\n", "").splitlines():
        if not COMMAND.search(line):
            continue
        lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        statement = []
        for token in [*lexer, ";"]:
            if token and all(char in ";&|" for char in token):
                if statement and statement[0] in {"set", "trap", "source", "."}:
                    yield statement[0], statement[1:]
                statement = []
            else:
                statement.append(token)


def scan(root):
    scripts = root / "scripts"
    checked = 0
    failures = []
    files = sorted(scripts.rglob("*.sh"))
    for path in files:
        if path.relative_to(scripts).as_posix() in SKIPPED:
            continue
        nounset = False
        exit_trap = False
        guarded = False
        helper = False
        for command, args in shell_commands(path.read_text()):
            if command == "set":
                for index, arg in enumerate(args):
                    if arg == "--":
                        break
                    if arg == "-o" and args[index + 1:index + 2] == ["nounset"]:
                        nounset = True
                    elif arg.startswith("-") and "u" in arg:
                        nounset = True
            elif command in {"source", "."} and args:
                helper |= args[0].endswith("/fail-closed-exit.sh")
            elif command == "trap":
                if args[:1] == ["--"]:
                    args = args[1:]
                if len(args) < 2 or args[0] == "-":
                    continue
                if {"EXIT", "0"}.intersection(args[1:]):
                    exit_trap = True
                    handler = shlex.split(args[0])
                    guarded |= bool(handler and handler[0] == "fail_closed_exit")
        if nounset and exit_trap:
            checked += 1
            if not (helper and guarded):
                failures.append(str(path.relative_to(root)))

    print(f"fail-closed EXIT scan: {len(files)} shell files, {checked} nounset/EXIT scripts")
    if checked == 0:
        print("refused: no nounset/EXIT scripts found; the scan did not look", file=sys.stderr)
        return 1
    for path in failures:
        print(f"{path}: source fail-closed-exit.sh and trap fail_closed_exit on EXIT", file=sys.stderr)
    return int(bool(failures))


if __name__ == "__main__":
    sys.exit(scan(Path(sys.argv[1] if len(sys.argv) > 1 else ".")))
