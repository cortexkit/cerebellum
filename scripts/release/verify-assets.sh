#!/usr/bin/env bash
# Check the exact release inventory and verify each ZIP against its .sha256 file.
set -euo pipefail

case ${1:-} in
  --tag-revision)
    tag=${2:?missing release tag}
    repo=${GITHUB_REPOSITORY:?missing GitHub repository}
    [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]
    ref=$(gh api "repos/$repo/git/ref/tags/$tag")
    [[ $(jq -er .ref <<< "$ref") == "refs/tags/$tag" ]]
    # Follow annotated tags through Git's tag objects, without resolving a same-named branch.
    object=$(jq -ce .object <<< "$ref")
    for ((depth=0; depth<8; depth++)); do
      sha=$(jq -er '.sha | select(test("^[a-f0-9]{40}$"))' <<< "$object")
      case $(jq -er .type <<< "$object") in
        commit) printf '%s\n' "$sha"; exit 0 ;;
        tag) object=$(gh api "repos/$repo/git/tags/$sha" | jq -ce .object) ;;
        *) break ;;
      esac
    done
    echo 'Release tag does not resolve to a commit.' >&2
    exit 1 ;;
  --release-manifest)
    revision=${2:?missing source revision}
    host=${3:?missing host version}
    floor=${4:?missing core floor}
    if [[ ! "$floor" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
      echo 'REQUIRES_CORE must be the confirmed MAJOR.MINOR.PATCH core floor.' >&2
      exit 1
    fi
    jq -n --arg floor "$floor" --arg module "$revision" --arg host "$host" \
      '{requires_core: $floor, binaries: {"ck-cerebellum": {reports: $module}, "ck-cerebellum-native-host": {reports: $host}}}'
    exit ;;
  --matrix)
    # Both workflows use this mapping, including for cross-architecture trailer checks.
    jq -nc '{include: [
      {platform:"darwin-arm64", os:"darwin", runner:"macos-latest", target:"aarch64-apple-darwin"},
      {platform:"linux-x64", os:"linux", runner:"ubuntu-24.04", target:"x86_64-unknown-linux-gnu"},
      {platform:"linux-arm64", os:"linux", runner:"ubuntu-24.04-arm", target:"aarch64-unknown-linux-gnu"},
      {platform:"windows-x64", os:"windows", runner:"windows-latest", target:"x86_64-pc-windows-msvc"},
      {platform:"windows-arm64", os:"windows", runner:"windows-11-arm", target:"aarch64-pc-windows-msvc"}
    ]}'
    exit ;;
  --inventory)
    shift
    python3 - "$@" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

assets = Path(sys.argv[1])
inventory = {p.name: digest(p) for p in sorted(assets.iterdir()) if p.is_file() and not p.is_symlink()}
print(json.dumps(inventory, separators=(",", ":")))
PY
    exit ;;
  --executables)
    matrix=$(bash "$0" --matrix)
    jq -nc --argjson matrix "$matrix" --argjson open "${2:?missing open platforms object}" '
      [ $matrix.include[] | select(.os as $os | $open | has($os)) as $entry |
        {"ck-cerebellum": "cerebellum", "ck-cerebellum-native-host": "host"} | to_entries[] |
        {key: (.key + "-" + $entry.platform + ".zip"), value: {role: .value, target: $entry.target}}
      ] | from_entries'
    exit ;;
  --verify-trailers)
    archives_dir=${2:?missing asset directory}
    open=${3:?missing open platforms object}
    verifier=${4:?missing peer-trailer path}
    matrix=$(bash "$0" --matrix)
    python3 - "$archives_dir" "$open" "$verifier" "$matrix" <<'PY'
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

assets, open_platforms, verifier, matrix = sys.argv[1:]
open_platforms = json.loads(open_platforms)
for entry in json.loads(matrix)["include"]:
    platform, os, target = (entry[key] for key in ("platform", "os", "target"))
    if os == "darwin":
        continue
    roles = {"ck-cerebellum": "cerebellum"}
    if os in open_platforms:
        roles["ck-cerebellum-native-host"] = "host"
    for binary, role in roles.items():
        name = binary + (".exe" if os == "windows" else "")
        archive = Path(assets) / f"{binary}-{platform}.zip"
        with zipfile.ZipFile(archive) as package, tempfile.TemporaryDirectory() as tmp:
            if package.namelist() != [name]:
                sys.exit(f"{archive}: expected exactly {name}")
            # Never unpack paths supplied by the ZIP or execute candidate code.
            image = Path(tmp) / name
            with package.open(name) as src, image.open("wb") as dst:
                shutil.copyfileobj(src, dst)
            args = ["verify", image, role, target] if os in open_platforms else ["assert-unsigned", image]
            subprocess.run([verifier, *args], check=True)
PY
    exit ;;
esac

assets=$(cd "${1:?usage: $0 <assets-dir> <expected-manifest>}" && pwd)
manifest="${2:?usage: $0 <assets-dir> <expected-manifest>}"
open=${3:-'{}'}
jq -e 'type == "object" and all(to_entries[];
  (.key == "linux" or .key == "windows") and
  (.value | type == "string" and length > 0 and . != "ci-unreviewed"))' <<< "$open" >/dev/null
matrix=$(bash "$0" --matrix)
cmp "$manifest" "$assets/release-manifest.json"
cd "$assets"

expected=$(jq -r --argjson open "$open" '.include[] | .platform as $platform |
  ("ck-cerebellum", (if .os == "darwin" or (.os as $os | $open | has($os))
    then "ck-cerebellum-native-host", "ck-cerebellum-extension" else empty end)) + "-" + $platform + ".zip"' <<< "$matrix")
archives=()
while IFS= read -r archive; do archives+=("$archive"); done <<< "$expected"
shopt -s nullglob dotglob
files=(*)
if [[ ${#files[@]} != $((2 * ${#archives[@]} + 1)) ]]; then
  printf 'Unexpected asset count: expected exactly %s ZIPs, their sidecars, and release-manifest.json.\n' "${#archives[@]}" >&2
  exit 1
fi

for file in "${files[@]}"; do
  [[ -f $file && ! -L $file ]] || { echo "Not a regular asset: $file" >&2; exit 1; }
done
for archive in "${archives[@]}"; do
  actual=$(shasum -a 256 "$archive")
  if ! cmp -s "$archive.sha256" <(printf '%s\n' "$actual"); then
    echo "Missing or incorrect checksum: $archive.sha256" >&2
    exit 1
  fi
  echo "Verified: $archive"
done
