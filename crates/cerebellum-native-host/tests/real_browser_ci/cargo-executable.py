"""Print the exact executable path, including for Cargo's build-dir layout."""

import json
import sys

target = sys.argv[1]
artifacts = [json.loads(line) for line in sys.stdin]
path, = [
    record["executable"]
    for record in artifacts
    if record["reason"] == "compiler-artifact"
    and record["target"]["name"] == target
    and record.get("executable")
]
print(path)
