#!/usr/bin/env bash
# Assert every module file under a crate's src/ is declared by its parent module.
#
# A module that exists on disk but is not declared compiles only where something
# includes it explicitly — typically a test binary via `#[path]`. That is a
# legitimate arrangement while a slice that does not own the crate root delivers
# a module, but it is indistinguishable from a module nobody ever wired up:
# dead code inside it is never reported, and nothing outside a test can call it.
#
# The walk is recursive, because the property is the same at every depth and a
# top-level-only check reports a clean tree while an undeclared module sits one
# directory down. Each file's parent is the module that must declare it:
# src/a.rs and src/a/mod.rs are declared by src/lib.rs; src/a/b.rs and
# src/a/b/mod.rs are declared by src/a/mod.rs, or by src/a.rs when the crate
# uses Rust's non-mod.rs layout for module `a`.
#
# Deliberately test-only modules belong in EXPECTED_UNWIRED below, so the
# decision is recorded rather than inferred from an absence.

set -euo pipefail

cd "$(dirname "$0")/.."

# Modules intentionally excluded from their parent, each with a reason.
# Format: "<crate>::<path::to::module>"
EXPECTED_UNWIRED=()

failed=0

# Denominators, because an empty scan and a clean scan print the same line.
# Pointing these loops at a directory that does not exist exits 0 with "every
# module is declared" -- a check that cannot see anything reports everything it
# saw as healthy. This repository always has crates and always has examples, so
# zero is never a legitimate answer here and a floor is the cheap, strong fix.
crates_scanned=0
sources_scanned=0
examples_scanned=0

for crate_dir in crates/*/; do
  [ -d "$crate_dir" ] || continue
  crates_scanned=$((crates_scanned + 1))
  crate="$(basename "$crate_dir")"
  src="${crate_dir}src"
  [ -d "$src" ] || continue
  # Every module file the source tree declares, including `mod y;` inside an
  # inline `mod x { }` (which lives at x/y.rs with no file parent).
  declared="$(python3 "$(dirname "$0")/lib/declared-modules.py" "$src")" || {
    echo "declared-modules.py failed for $src" >&2
    exit 1
  }
  while IFS= read -r file; do
    # Counted here rather than at the loop's end: the body continues early for
    # most files, so a tail increment counts almost nothing and reads as a
    # broken scan.
    sources_scanned=$((sources_scanned + 1))
    relative="${file#"$src"/}"
    case "$relative" in
      lib.rs | main.rs) continue ;;
    esac

    if [ "$(basename "$relative")" = "mod.rs" ]; then
      # src/a/b/mod.rs declares module `b` inside src/a.
      module_path="$(dirname "$relative")"
    else
      module_path="${relative%.rs}"
    fi

    module="$(basename "$module_path")"
    parent_dir="$(dirname "$module_path")"

    if [ "$parent_dir" = "." ]; then
      parent="$src/lib.rs"
    else
      parent="$src/$parent_dir/mod.rs"
      # Rust also accepts src/a.rs as the parent of src/a/b.rs. Exactly one
      # of the two may exist, or rustc refuses the crate.
      if [ ! -f "$parent" ] && [ -f "$src/$parent_dir.rs" ]; then
        parent="$src/$parent_dir.rs"
      fi
    fi

    # Declared from inside an inline module of another file: Rust resolves
    # it, and the scanner has already confirmed the declaration.
    if grep -qxF "$(cd "$(dirname "$file")" && pwd -P)/$(basename "$file")" <<<"$declared"; then
      continue
    fi

    # A parent that does not exist is its own defect: the directory holds
    # modules that nothing can declare.
    if [ ! -f "$parent" ]; then
      echo "unwired module: ${crate}::${module_path//\//::} has no parent module at ${parent#./}"
      failed=1
      continue
    fi

    if grep -qE "^[[:space:]]*(pub(\([a-z]+\))? )?mod ${module};" "$parent"; then
      continue
    fi

    qualified="${crate}::${module_path//\//::}"
    skip=0
    for allowed in "${EXPECTED_UNWIRED[@]:-}"; do
      [ "$allowed" = "$qualified" ] && skip=1
    done
    [ "$skip" -eq 1 ] && continue

    echo "unwired module: ${qualified} is not declared in ${parent#./}"
    failed=1
  done < <(find "$src" -name '*.rs' | sort)
done

if [ "$failed" -ne 0 ]; then
  echo
  echo "Declare the module in its parent module, or add it to EXPECTED_UNWIRED in"
  echo "$0 with the reason it is deliberately test-only."
  exit 1
fi

echo "module wiring: $sources_scanned modules across $crates_scanned crates, every one declared by its parent"

# Assert every example carrying tests declares an example target with test = true.
#
# Cargo defaults an example target to test = false, so `cargo test --workspace`
# BUILDS the example and skips its #[cfg(test)] module. The tests still pass
# whenever someone invokes them directly, which is what makes this hard to see:
# they are neither broken nor unwritten, merely absent from the only command
# anyone runs. Seven such tests sat in this repository until a contributor found
# the same thing on their own branch.
#
# Worse than missing coverage, because a workspace count that does not move
# reads as a count that had nothing to add.
example_failed=0
for example in crates/*/examples/*.rs; do
  [ -e "$example" ] || continue
  examples_scanned=$((examples_scanned + 1))
  grep -qE '^\s*#\[(tokio::)?test\]' "$example" || continue

  crate_dir="${example%/examples/*}"
  name="$(basename "$example" .rs)"
  manifest="$crate_dir/Cargo.toml"

  # The declaration must name THIS example and enable tests for it. Reading the
  # block rather than grepping for the name separately, so a test = true meant
  # for a different example cannot satisfy this one. The verdict is compared as
  # a value rather than piped into grep -q: a status-deciding pipeline whose
  # last stage can close early inverts under pipefail the day the producer
  # outgrows the pipe buffer, and a value comparison cannot.
  verdict="$(awk -v want="$name" '
      /^\[\[example\]\]/ { in_block = 1; found_name = 0; found_test = 0; next }
      /^\[/ && !/^\[\[example\]\]/ { in_block = 0 }
      in_block && $0 ~ "name[[:space:]]*=[[:space:]]*\"" want "\"" { found_name = 1 }
      in_block && $0 ~ /test[[:space:]]*=[[:space:]]*true/ { found_test = 1 }
      found_name && found_test { print "ok"; exit }
    ' "$manifest")"
  if [ "$verdict" != ok ]; then
    echo "example tests never run: $example has tests, but $manifest does not declare"
    echo "  [[example]] name = \"$name\" with test = true"
    example_failed=1
  fi
done

if [ "$crates_scanned" -eq 0 ] || [ "$sources_scanned" -eq 0 ] || [ "$examples_scanned" -eq 0 ]; then
  echo "this check could not look: crates=$crates_scanned sources=$sources_scanned examples=$examples_scanned"
  echo "A zero here means a broken path or glob, not a healthy tree. Refusing"
  echo "rather than reporting a clean scan it never performed."
  exit 1
fi

if [ "$example_failed" -ne 0 ]; then
  echo
  echo "Declare the example target with test = true, or the tests build and never run."
  exit 1
fi

echo "example tests: $examples_scanned examples, every one carrying tests declares a target that runs them"

# Assert every release identifier the shipped code reads is one the release
# build exports.
#
# A capability is advertised only when the build carries its review revision,
# read at compile time through option_env!. If release-build.sh's ATTESTATIONS
# list leaves an identifier out, the release build never exports it, so the
# capability ships switched off with nothing failing: the build succeeds and
# ships less than intended. The private input route's identifier was missing
# from the list exactly this way. Only the crates' src/ trees count: examples
# read probe-only switches the release never sets.
extract_release_identifiers() {
  find "$@" -type f -name '*.rs' -exec perl -0777 -ne '
    while (/option_env\s*!\s*\(\s*(?:r#*)?"(CEREBELLUM_[A-Z0-9_]+)"/g) {
      print "$1\n";
    }
  ' {} + | sort -u
}

find_unlisted_identifiers() {
  local read_identifiers="$1"
  local listed_identifiers="$2"
  comm -23 <(printf '%s\n' "$read_identifiers" | sort -u) \
           <(printf '%s\n' "$listed_identifiers" | sort -u)
}

# Built-in controls run before the real check.
#
# A scan that reports nothing looks identical whether the tree is clean or
# the scan is blind. Planting positive controls (split lines, internal spaces,
# raw strings) proves layout variations are extracted; planting a decoy proves
# non-matching prefixes are ignored; planting an unlisted identifier proves
# missing attestations fail the comparison.
control_scratch="$(mktemp -d "${TMPDIR:-/tmp}/module-wiring-control.XXXXXX")"
trap 'rm -rf "$control_scratch"' EXIT INT TERM

cat >"$control_scratch/planted.rs" <<'EOF'
// split-form
let _ = option_env!(
    "CEREBELLUM_CONTROL_SPLIT"
);

// spaced-form
let _ = option_env!( "CEREBELLUM_CONTROL_SPACED" );

// raw-string form (hash-delimited)
let _ = option_env!(r#"CEREBELLUM_CONTROL_RAW_HASH"#);

// raw-string form (plain)
let _ = option_env!(r"CEREBELLUM_CONTROL_RAW");

// plain form
let _ = option_env!("CEREBELLUM_CONTROL_PLAIN");

// decoy that must not be extracted
let _ = option_env!("OTHER_X");

// identifier missing from listed attestations
let _ = option_env!("CEREBELLUM_CONTROL_MISSING");
EOF

control_read="$(extract_release_identifiers "$control_scratch")"

# 1. Split-form control
if ! grep -qx "CEREBELLUM_CONTROL_SPLIT" <<< "$control_read"; then
  echo "check is blind: split-form control failed to extract CEREBELLUM_CONTROL_SPLIT" >&2
  exit 2
fi

# 2. Spaced-form control
if ! grep -qx "CEREBELLUM_CONTROL_SPACED" <<< "$control_read"; then
  echo "check is blind: spaced-form control failed to extract CEREBELLUM_CONTROL_SPACED" >&2
  exit 2
fi

# 3. Raw-string controls
if ! grep -qx "CEREBELLUM_CONTROL_RAW_HASH" <<< "$control_read"; then
  echo "check is blind: raw-string control failed to extract CEREBELLUM_CONTROL_RAW_HASH" >&2
  exit 2
fi

if ! grep -qx "CEREBELLUM_CONTROL_RAW" <<< "$control_read"; then
  echo "check is blind: raw-string control failed to extract CEREBELLUM_CONTROL_RAW" >&2
  exit 2
fi

# 4. Plain-form control
if ! grep -qx "CEREBELLUM_CONTROL_PLAIN" <<< "$control_read"; then
  echo "check is blind: plain-form control failed to extract CEREBELLUM_CONTROL_PLAIN" >&2
  exit 2
fi

# 5. Decoy control
if grep -qx "OTHER_X" <<< "$control_read"; then
  echo "check is blind: decoy control failed: OTHER_X was erroneously extracted" >&2
  exit 2
fi

# 6. Missing-identifier comparison control
control_listed="$(cat <<'EOF'
CEREBELLUM_CONTROL_PLAIN
CEREBELLUM_CONTROL_RAW
CEREBELLUM_CONTROL_RAW_HASH
CEREBELLUM_CONTROL_SPACED
CEREBELLUM_CONTROL_SPLIT
EOF
)"

control_unlisted="$(find_unlisted_identifiers "$control_read" "$control_listed")"
if [ "$control_unlisted" != "CEREBELLUM_CONTROL_MISSING" ]; then
  echo "check is blind: missing-identifier control failed: expected 'CEREBELLUM_CONTROL_MISSING', got '${control_unlisted:-<none>}'" >&2
  exit 2
fi

rm -rf "$control_scratch"
trap - EXIT INT TERM

# Real scan across crate sources and scripts/release-build.sh.
read_names="$(extract_release_identifiers crates/*/src)"
listed_names="$(awk '/^readonly ATTESTATIONS=\(/ { in_list = 1; next }
    in_list && /^\)/ { exit }
    in_list { gsub(/[[:space:]]/, ""); if ($0 != "") print }' scripts/release-build.sh | sort -u)"
read_count="$(grep -c . <<< "$read_names" || true)"
listed_count="$(grep -c . <<< "$listed_names" || true)"
if [ "$read_count" -eq 0 ] || [ "$listed_count" -eq 0 ]; then
  echo "this check could not look: identifiers read=$read_count listed=$listed_count"
  echo "A zero means a broken path or pattern, not a healthy tree."
  exit 1
fi
unlisted="$(find_unlisted_identifiers "$read_names" "$listed_names")"
if [ -n "$unlisted" ]; then
  echo "release identifiers the code reads but release-build.sh never exports:"
  printf '  %s\n' $unlisted
  echo "Add each to ATTESTATIONS in scripts/release-build.sh, or its capability ships switched off."
  exit 1
fi
echo "release identifiers: $read_count read by the code, every one exported by release-build.sh"
