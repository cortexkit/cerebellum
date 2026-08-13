#!/usr/bin/env bash
# List every bool whose default value is chosen by `#[derive(Default)]`.
#
# A derived Default answers "what is this flag when nobody sets it" with false,
# and it answers silently: no reader of any constructor sees the decision, and
# `..Self::default()` is where it hides, because that syntax reads as "everything
# else stays as it was" rather than as a choice.
#
# That is fine for most flags and a security defect for one kind. The
# discriminator is what FALSE MEANS:
#
#   SAFE     false means "this hazard is not present" or "this has not happened
#            yet" -- an absent claim. ConnectorConfig's bypass flags are this
#            shape, and its `safe()` refuses construction unless all are false.
#
#   DEFECT   false means "this check does not run". The gate is then off in
#            every construction path that does not name it, which is every path
#            a reader assumes is the safe one.
#
# Found in shipped code by the second shape: BrowserPlane held
# `authorization_enabled: bool` with a derived Default, so wire navigation was
# served with its grant check skipped rather than refused (fixed caa03d4, by
# deleting the flag -- a knob whose only correct value is on is not a knob).
#
# This prints CANDIDATES, not findings. The verdict needs a human reading of
# what false means at each site, which is why it does not exit nonzero on a hit.
# Printing is the load-bearing half: a list of every place a macro is making the
# call cannot be mistaken for silence.
set -euo pipefail

root=${1:-crates}

python3 - "$root" <<'PY'
import re, sys, pathlib

root = pathlib.Path(sys.argv[1])
hits = []
for path in sorted(root.rglob("*.rs")):
    text = path.read_text()
    # Skip test modules by their brace-balanced extent rather than by cutting at
    # the marker: top-level code placed AFTER a test module is production code,
    # and a marker-offset cut reads it as test code.
    production, depth, in_test = [], 0, False
    for line in text.splitlines():
        if not in_test and line.lstrip().startswith("#[cfg(test)]"):
            in_test, depth = True, 0
            continue
        if in_test:
            depth += line.count("{") - line.count("}")
            if depth <= 0 and "}" in line:
                in_test = False
            continue
        production.append(line)
    body = "\n".join(production)

    for match in re.finditer(
        r"#\[derive\(([^)]*)\)\]\s*(?:pub\s+)?struct\s+(\w+)\s*\{([^}]*)\}", body, re.S
    ):
        derives, struct, fields = match.groups()
        if "Default" not in derives:
            continue
        for field in re.finditer(r"(?:pub\s+)?(\w+)\s*:\s*bool\s*,", fields):
            hits.append((path, struct, field.group(1)))

for path, struct, field in hits:
    print(f"{path}: {struct}.{field}")

print()
print(f"{len(hits)} bool default(s) supplied by derive(Default).")
print("For each, ask what FALSE means. If it means a check does not run, the")
print("macro is deciding whether that check runs -- delete the flag rather than")
print("defaulting it true, or the same bool is one edit from the same outcome.")
PY
