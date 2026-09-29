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
# src/a/b/mod.rs are declared by src/a/mod.rs.
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
    fi

    # A parent that does not exist is its own defect: the directory holds
    # modules that nothing can declare.
    if [ ! -f "$parent" ]; then
      echo "unwired module: ${crate}::${module_path//\//::} has no parent module at ${parent#./}"
      failed=1
      continue
    fi

    if grep -qE "^[[:space:]]*(pub )?mod ${module};" "$parent"; then
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
read_names="$(grep -rhoE 'option_env!\("CEREBELLUM_[A-Z_]+"\)' crates/*/src \
  | sed -E 's/.*"(CEREBELLUM_[A-Z_]+)".*/\1/' | sort -u)"
listed_names="$(awk '/^readonly ATTESTATIONS=\(/ { in_list = 1; next }
    in_list && /^\)/ { exit }
    in_list { gsub(/[[:space:]]/, ""); if ($0 != "") print }' scripts/release-build.sh | sort -u)"
read_count="$(printf '%s\n' "$read_names" | grep -c . || true)"
listed_count="$(printf '%s\n' "$listed_names" | grep -c . || true)"
if [ "$read_count" -eq 0 ] || [ "$listed_count" -eq 0 ]; then
  echo "this check could not look: identifiers read=$read_count listed=$listed_count"
  echo "A zero means a broken path or pattern, not a healthy tree."
  exit 1
fi
unlisted="$(comm -23 <(printf '%s\n' "$read_names") <(printf '%s\n' "$listed_names"))"
if [ -n "$unlisted" ]; then
  echo "release identifiers the code reads but release-build.sh never exports:"
  printf '  %s\n' $unlisted
  echo "Add each to ATTESTATIONS in scripts/release-build.sh, or its capability ships switched off."
  exit 1
fi
echo "release identifiers: $read_count read by the code, every one exported by release-build.sh"
